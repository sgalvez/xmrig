// Read-only GPU enumeration. No context, kernels, mining jobs or network calls.
// Match XMRig OclConfig::platform() and OclPlatform::devices(): first AMD
// platform, CL_DEVICE_TYPE_GPU, and the original zero-based device ordering.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PersonalMining {
    public sealed class OpenClGpu {
        public int PlatformIndex;
        public string PlatformVersion;
        public int Id;
        public string Name;
        public string BoardName;
        public ulong MemoryBytes;
    }

    public static class OpenClInventory {
        [DllImport("OpenCL.dll", EntryPoint="clGetPlatformIDs")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int Platforms(uint count, [Out] IntPtr[] ids, out uint total);
        [DllImport("OpenCL.dll", EntryPoint="clGetPlatformInfo")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int PlatformInfo(IntPtr id, uint key, UIntPtr size, [Out] byte[] value, out UIntPtr used);
        [DllImport("OpenCL.dll", EntryPoint="clGetDeviceIDs")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int Devices(IntPtr platform, ulong type, uint count, [Out] IntPtr[] ids, out uint total);
        [DllImport("OpenCL.dll", EntryPoint="clGetDeviceInfo")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int DeviceInfo(IntPtr id, uint key, UIntPtr size, [Out] byte[] value, out UIntPtr used);

        private static void Check(int result) {
            if (result != 0) throw new InvalidOperationException("OpenCL error: " + result);
        }
        private static string Text(IntPtr id, uint key, bool platform, bool optional) {
            UIntPtr used;
            byte[] value = new byte[4096];
            int result = platform ? PlatformInfo(id, key, (UIntPtr)value.Length, value, out used)
                                  : DeviceInfo(id, key, (UIntPtr)value.Length, value, out used);
            if (optional && result != 0) return "";
            Check(result);
            return Encoding.UTF8.GetString(value).TrimEnd('\0');
        }
        public static OpenClGpu[] ReadAmd() {
            uint count;
            Check(Platforms(0, null, out count));
            if (count == 0 || count > 128) throw new InvalidOperationException("No hay plataformas OpenCL validas.");
            IntPtr[] platforms = new IntPtr[count];
            Check(Platforms(count, platforms, out count));
            for (int p = 0; p < platforms.Length; p++) {
                if (!Text(platforms[p], 0x0903, true, false).Contains("Advanced Micro Devices")) continue;
                uint total;
                int result = Devices(platforms[p], 4, 0, null, out total); // CL_DEVICE_TYPE_GPU
                if (result == -1 || (result == 0 && total == 0))
                    throw new InvalidOperationException("La primera plataforma AMD no expone GPU; revisa el controlador.");
                Check(result);
                if (total > 128) throw new InvalidOperationException("Cantidad de GPU inesperada.");
                IntPtr[] devices = new IntPtr[total];
                Check(Devices(platforms[p], 4, total, devices, out total));
                var output = new List<OpenClGpu>();
                for (int i = 0; i < devices.Length; i++) {
                    UIntPtr used;
                    byte[] memory = new byte[8];
                    Check(DeviceInfo(devices[i], 0x101F, (UIntPtr)8, memory, out used));
                    output.Add(new OpenClGpu {
                        PlatformIndex = p, PlatformVersion = Text(platforms[p], 0x0901, true, false),
                        Id = i, Name = Text(devices[i], 0x102B, false, false),
                        BoardName = Text(devices[i], 0x4038, false, true), // CL_DEVICE_BOARD_NAME_AMD
                        MemoryBytes = BitConverter.ToUInt64(memory, 0)
                    });
                }
                return output.ToArray();
            }
            throw new InvalidOperationException("No se encontro una plataforma AMD compatible con la seleccion de XMRig.");
        }
    }
}
