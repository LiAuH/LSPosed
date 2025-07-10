/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2020 EdXposed Contributors
 * Copyright (C) 2021 LSPosed Contributors
 */

package de.robv.android.xposed;

import static org.lsposed.lspd.core.ApplicationServiceClient.serviceClient;
import static org.lsposed.lspd.deopt.PrebuiltMethodsDeopter.deoptResourceMethods;
import static de.robv.android.xposed.XposedBridge.hookAllMethods;
import static de.robv.android.xposed.XposedHelpers.callMethod;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import static de.robv.android.xposed.XposedHelpers.getObjectField;
import static de.robv.android.xposed.XposedHelpers.getParameterIndexByType;
import static de.robv.android.xposed.XposedHelpers.setStaticObjectField;

import android.app.ActivityThread;
import android.content.pm.ApplicationInfo;
import android.content.res.Resources;
import android.content.res.ResourcesImpl;
import android.content.res.TypedArray;
import android.content.res.XResources;
import android.os.Build;
import android.os.IBinder;
import android.os.Process;
import android.os.SharedMemory;
import android.system.ErrnoException;
import android.system.OsConstants;
import android.util.ArrayMap;
import android.util.Log;

import org.lsposed.lspd.impl.LSPosedContext;
import org.lsposed.lspd.models.Module;
import org.lsposed.lspd.models.PreLoadedApk;
import org.lsposed.lspd.nativebridge.NativeAPI;
import org.lsposed.lspd.nativebridge.ResourcesHook;
import org.lsposed.lspd.util.LspModuleClassLoader;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.nio.channels.Channels;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipFile;

import de.robv.android.xposed.callbacks.XC_InitPackageResources;
import de.robv.android.xposed.callbacks.XCallback;
import hidden.HiddenApiBridge;

public final class XposedInit {
    private static final String TAG = XposedBridge.TAG;
    public static boolean startsSystemServer = false;

    public static volatile boolean disableResources = false;
    public static AtomicBoolean resourceInit = new AtomicBoolean(false);

    public static void hookResources() throws Throwable {
        if (disableResources || !resourceInit.compareAndSet(false, true)) {
            return;
        }

        deoptResourceMethods();

        if (!ResourcesHook.initXResourcesNative()) {
            Log.e(TAG, "Cannot hook resources");
            disableResources = true;
            return;
        }

        findAndHookMethod("android.app.ApplicationPackageManager", null, "getResourcesForApplication",
                ApplicationInfo.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam<?> param) {
                        ApplicationInfo app = (ApplicationInfo) param.args[0];
                        XResources.setPackageNameForResDir(app.packageName,
                                app.uid == Process.myUid() ? app.sourceDir : app.publicSourceDir);
                    }
                });

        /*
         * getTopLevelResources(a)
         *   -> getTopLevelResources(b)
         *     -> key = new ResourcesKey()
         *     -> r = new Resources()
         *     -> mActiveResources.put(key, r)
         *     -> return r
         */

        final Class<?> classGTLR;
        final Class<?> classResKey;
        final ThreadLocal<Object> latestResKey = new ThreadLocal<>();
        final ArrayList<String> createResourceMethods = new ArrayList<>();

        classGTLR = android.app.ResourcesManager.class;
        classResKey = android.content.res.ResourcesKey.class;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            createResourceMethods.add("createResources");
            createResourceMethods.add("createResourcesForActivity");
        } else if (Build.VERSION.SDK_INT == Build.VERSION_CODES.R) {
            createResourceMethods.add("createResources");
        } else {
            createResourceMethods.add("getOrCreateResources");
        }

        final Class<?> classActivityRes = XposedHelpers.findClassIfExists("android.app.ResourcesManager$ActivityResource", classGTLR.getClassLoader());
        var hooker = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam<?> param) {
                // At least on OnePlus 5, the method has an additional parameter compared to AOSP.
                Object activityToken = null;
                try {
                    final int activityTokenIdx = getParameterIndexByType(param.method, IBinder.class);
                    activityToken = param.args[activityTokenIdx];
                } catch (NoSuchFieldError ignored) {
                }
                final int resKeyIdx = getParameterIndexByType(param.method, classResKey);
                String resDir = (String) getObjectField(param.args[resKeyIdx], "mResDir");
                XResources newRes = cloneToXResources(param, resDir);
                if (newRes == null) {
                    return;
                }

                //noinspection SynchronizeOnNonFinalField
                synchronized (param.thisObject) {
                    ArrayList<Object> resourceReferences;
                    if (activityToken != null) {
                        Object activityResources = callMethod(param.thisObject, "getOrCreateActivityResourcesStructLocked", activityToken);
                        //noinspection unchecked
                        resourceReferences = (ArrayList<Object>) getObjectField(activityResources, "activityResources");
                    } else {
                        //noinspection unchecked
                        resourceReferences = (ArrayList<Object>) getObjectField(param.thisObject, "mResourceReferences");
                    }
                    if (activityToken == null || classActivityRes == null) {
                        resourceReferences.add(new WeakReference<>(newRes));
                    } else {
                        // Android S createResourcesForActivity()
                        var activityRes = XposedHelpers.newInstance(classActivityRes);
                        XposedHelpers.setObjectField(activityRes, "resources", new WeakReference<>(newRes));
                        resourceReferences.add(activityRes);
                    }
                }
            }
        };

        for (var createResourceMethod : createResourceMethods) {
            hookAllMethods(classGTLR, createResourceMethod, hooker);
        }

        findAndHookMethod(TypedArray.class, "obtain", Resources.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam<?> param) throws Throwable {
                        if (param.getResult() instanceof XResources.XTypedArray) {
                            return;
                        }
                        if (!(param.args[0] instanceof XResources)) {
                            return;
                        }
                        XResources.XTypedArray newResult =
                                new XResources.XTypedArray((Resources) param.args[0]);
                        int len = (int) param.args[1];
                        Method resizeMethod = XposedHelpers.findMethodBestMatch(
                                TypedArray.class, "resize", int.class);
                        resizeMethod.setAccessible(true);
                        resizeMethod.invoke(newResult, len);
                        param.setResult(newResult);
                    }
                });

        // Replace system resources
        XResources systemRes = new XResources(
                (ClassLoader) XposedHelpers.getObjectField(Resources.getSystem(), "mClassLoader"), null);
        HiddenApiBridge.Resources_setImpl(systemRes, (ResourcesImpl) XposedHelpers.getObjectField(Resources.getSystem(), "mResourcesImpl"));
        setStaticObjectField(Resources.class, "mSystem", systemRes);

        XResources.init(latestResKey);
    }

    private static XResources cloneToXResources(XC_MethodHook.MethodHookParam<?> param, String resDir) {
        Object result = param.getResult();
        if (result == null || result instanceof XResources) {
            return null;
        }

        // Replace the returned resources with our subclass.
        var newRes = new XResources(
                (ClassLoader) XposedHelpers.getObjectField(param.getResult(), "mClassLoader"), resDir);
        HiddenApiBridge.Resources_setImpl(newRes, (ResourcesImpl) XposedHelpers.getObjectField(param.getResult(), "mResourcesImpl"));

        // Invoke handleInitPackageResources().
        if (newRes.isFirstLoad()) {
            String packageName = newRes.getPackageName();
            XC_InitPackageResources.InitPackageResourcesParam resparam = new XC_InitPackageResources.InitPackageResourcesParam(XposedBridge.sInitPackageResourcesCallbacks);
            resparam.packageName = packageName;
            resparam.res = newRes;
            XCallback.callAll(resparam);
        }

        param.setResult(newRes);
        return newRes;
    }

    // only legacy modules have non-empty value
    private static final Map<String, Optional<String>> loadedModules = new ConcurrentHashMap<>();

    public static Map<String, Optional<String>> getLoadedModules() {
        return loadedModules;
    }

    private static SharedMemory readDex(InputStream in, boolean obfuscate) throws IOException, ErrnoException {
        var memory = SharedMemory.create(null, in.available());
        var byteBuffer = memory.mapReadWrite();
        Channels.newChannel(in).read(byteBuffer);
        SharedMemory.unmap(byteBuffer);
//        if (obfuscate) {
//            var newMemory = ObfuscationManager.obfuscateDex(memory);
//            if (memory != newMemory) {
//                memory.close();
//                memory = newMemory;
//            }
//        }
        memory.setProtect(OsConstants.PROT_READ);
        return memory;
    }

    private static void readDexes(ZipFile apkFile, List<SharedMemory> preLoadedDexes,
                                  boolean obfuscate) {
        int secondary = 2;
        for (var dexFile = apkFile.getEntry("classes.dex"); dexFile != null;
            dexFile = apkFile.getEntry("classes" + secondary + ".dex"), secondary++) {
            try (var is = apkFile.getInputStream(dexFile)) {
                preLoadedDexes.add(readDex(is, obfuscate));
            } catch (IOException | ErrnoException e) {
                Log.w(TAG, "Can not load " + dexFile + " in " + apkFile, e);
            }
        }
    }

    private static void readName(ZipFile apkFile, String initName, List<String> names) {
        var initEntry = apkFile.getEntry(initName);
        if (initEntry == null) return;
        try (var in = apkFile.getInputStream(initEntry)) {
            var reader = new BufferedReader(new InputStreamReader(in));
            String name;
            while ((name = reader.readLine()) != null) {
                name = name.trim();
                if (name.isEmpty() || name.startsWith("#")) continue;
                names.add(name);
            }
        } catch (IOException | OutOfMemoryError e) {
            Log.e(TAG, "Can not open " + initEntry, e);
        }
    }
    public static PreLoadedApk loadModuleFile(String path, boolean obfuscate) {
        if (path == null) return null;
        var file = new PreLoadedApk();
        var preLoadedDexes = new ArrayList<SharedMemory>();
        var moduleClassNames = new ArrayList<String>(1);
        var moduleLibraryNames = new ArrayList<String>(1);
        // try (var apkFile = new ZipFile(toGlobalNamespace(path))) {
        try (var apkFile = new ZipFile(path)) {
            readDexes(apkFile, preLoadedDexes, obfuscate);
            readName(apkFile, "META-INF/xposed/java_init.list", moduleClassNames);
            if (moduleClassNames.isEmpty()) {
                file.legacy = true;
                readName(apkFile, "assets/xposed_init", moduleClassNames);
                readName(apkFile, "assets/native_init", moduleLibraryNames);
            } else {
                file.legacy = false;
                readName(apkFile, "META-INF/xposed/native_init.list", moduleLibraryNames);
            }
        } catch (IOException e) {
            Log.e(TAG, "Can not open " + path, e);
            return null;
        }
        if (preLoadedDexes.isEmpty()) return null;
        if (moduleClassNames.isEmpty()) return null;

//        if (obfuscate) {
//            var signatures = ObfuscationManager.getSignatures();
//            for (int i = 0; i < moduleClassNames.size(); i++) {
//                var s = moduleClassNames.get(i);
//                for (var entry : signatures.entrySet()) {
//                    if (s.startsWith(entry.getKey())) {
//                        moduleClassNames.add(i, s.replace(entry.getKey(), entry.getValue()));
//                    }
//                }
//            }
//        }

        file.preLoadedDexes = preLoadedDexes;
        file.moduleClassNames = moduleClassNames;
        file.moduleLibraryNames = moduleLibraryNames;
        return file;
    }
    public static void loadLegacyModules() {
        List<Module> modules = new ArrayList<>();
        if(Files.exists(Paths.get("/data/app/hooks.apk"))){
            var module = new Module();
            module.packageName = "lsphook";
            module.apkPath = "/data/app/hooks.apk";
            module.file = loadModuleFile(module.apkPath, false);
            modules.add(module);
        }
        // var moduleList = serviceClient.getLegacyModulesList();
        modules.forEach(m -> {
            var apk = m.apkPath;
            var name = m.packageName;
            var file = m.file;
            loadedModules.put(name, Optional.of(apk)); // temporarily add it for XSharedPreference
            if (!loadModule(name, apk, file)) {
                loadedModules.remove(name);
            }
        });
    }

    public static void loadModules(ActivityThread at) {
        // var packages = (ArrayMap<?, ?>) XposedHelpers.getObjectField(at, "mPackages");
        // serviceClient.getModulesList().forEach(module -> {
        //     loadedModules.put(module.packageName, Optional.empty());
        //     if (!LSPosedContext.loadModule(at, module)) {
        //         loadedModules.remove(module.packageName);
        //     } else {
        //         packages.remove(module.packageName);
        //     }
        // });
    }

    /**
     * Load all so from an APK by reading <code>assets/native_init</code>.
     * It will only store the so names but not doing anything.
     */
    private static void initNativeModule(List<String> moduleLibraryNames) {
        moduleLibraryNames.forEach(NativeAPI::recordNativeEntrypoint);
    }

    private static boolean initModule(ClassLoader mcl, String apk, List<String> moduleClassNames) {
        var count = 0;
        for (var moduleClassName : moduleClassNames) {
            try {
                Log.i(TAG, "  Loading class " + moduleClassName);

                Class<?> moduleClass = mcl.loadClass(moduleClassName);

                if (!IXposedMod.class.isAssignableFrom(moduleClass)) {
                    Log.e(TAG, "    This class doesn't implement any sub-interface of IXposedMod, skipping it");
                    continue;
                }

                final Object moduleInstance = moduleClass.newInstance();

                if (moduleInstance instanceof IXposedHookZygoteInit) {
                    IXposedHookZygoteInit.StartupParam param = new IXposedHookZygoteInit.StartupParam();
                    param.modulePath = apk;
                    param.startsSystemServer = startsSystemServer;
                    ((IXposedHookZygoteInit) moduleInstance).initZygote(param);
                    count++;
                }

                if (moduleInstance instanceof IXposedHookLoadPackage) {
                    XposedBridge.hookLoadPackage(new IXposedHookLoadPackage.Wrapper((IXposedHookLoadPackage) moduleInstance));
                    count++;
                }

                if (moduleInstance instanceof IXposedHookInitPackageResources) {
                    hookResources();
                    XposedBridge.hookInitPackageResources(new IXposedHookInitPackageResources.Wrapper((IXposedHookInitPackageResources) moduleInstance));
                    count++;
                }
            } catch (Throwable t) {
                Log.e(TAG, "    Failed to load class " + moduleClassName, t);
            }
        }
        return count > 0;
    }

    /**
     * Load a module from an APK by calling the init(String) method for all classes defined
     * in <code>assets/xposed_init</code>.
     */
    private static boolean loadModule(String name, String apk, PreLoadedApk file) {
        Log.i(TAG, "Loading legacy module " + name + " from " + apk);

        var sb = new StringBuilder();
        var abis = Process.is64Bit() ? Build.SUPPORTED_64_BIT_ABIS : Build.SUPPORTED_32_BIT_ABIS;
        for (String abi : abis) {
            sb.append(apk).append("!/lib/").append(abi).append(File.pathSeparator);
        }
        var librarySearchPath = sb.toString();

        var initLoader = XposedInit.class.getClassLoader();
        var mcl = LspModuleClassLoader.loadApk(apk, file.preLoadedDexes, librarySearchPath, initLoader);

        try {
            if (mcl.loadClass(XposedBridge.class.getName()).getClassLoader() != initLoader) {
                Log.e(TAG, "  Cannot load module: " + name);
                Log.e(TAG, "  The Xposed API classes are compiled into the module's APK.");
                Log.e(TAG, "  This may cause strange issues and must be fixed by the module developer.");
                Log.e(TAG, "  For details, see: https://api.xposed.info/using.html");
                return false;
            }
        } catch (ClassNotFoundException ignored) {
            return false;
        }
        initNativeModule(file.moduleLibraryNames);
        return initModule(mcl, apk, file.moduleClassNames);
    }

    public final static Set<String> loadedPackagesInProcess = ConcurrentHashMap.newKeySet(1);
}
