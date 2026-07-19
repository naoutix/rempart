using System.Security;
using Microsoft.Win32;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Implémentation réelle sur le registre Windows. Seule couche du projet à connaître
/// <c>Microsoft.Win32</c> — tout le reste travaille contre <see cref="IRegistryProvider"/>.
/// </summary>
public sealed class LiveRegistryProvider : IRegistryProvider
{
    public RegistryRead ReadValue(string keyPath, string valueName)
    {
        try
        {
            using var key = OpenKey(keyPath);
            if (key is null)
            {
                return RegistryRead.NotFound;
            }

            var raw = key.GetValue(valueName);
            if (raw is null)
            {
                return RegistryRead.NotFound;
            }

            var kind = key.GetValueKind(valueName);
            return RegistryRead.Found(Convert(kind, raw));
        }
        catch (SecurityException)
        {
            return RegistryRead.AccessDenied;
        }
        catch (UnauthorizedAccessException)
        {
            return RegistryRead.AccessDenied;
        }
    }

    public ReadStatus KeyExists(string keyPath)
    {
        try
        {
            using var key = OpenKey(keyPath);
            return key is null ? ReadStatus.NotFound : ReadStatus.Found;
        }
        catch (SecurityException)
        {
            return ReadStatus.AccessDenied;
        }
        catch (UnauthorizedAccessException)
        {
            return ReadStatus.AccessDenied;
        }
    }

    private static RegistryValue Convert(RegistryValueKind kind, object raw) => kind switch
    {
        RegistryValueKind.DWord or RegistryValueKind.QWord =>
            RegistryValue.OfNumber(System.Convert.ToInt64(raw)),
        RegistryValueKind.MultiString =>
            new RegistryValue("MultiString", string.Join("\n", (string[])raw), null),
        RegistryValueKind.Binary =>
            new RegistryValue("Binary", System.Convert.ToHexStringLower((byte[])raw), null),
        _ => new RegistryValue(kind.ToString(), raw.ToString(), null),
    };

    private static RegistryKey? OpenKey(string keyPath)
    {
        var separator = keyPath.IndexOf('\\');
        if (separator < 0)
        {
            throw new ArgumentException($"Chemin de registre sans sous-clé : {keyPath}", nameof(keyPath));
        }

        var hiveName = keyPath[..separator];
        var subKey = keyPath[(separator + 1)..];

        var hive = hiveName.ToUpperInvariant() switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
            "HKCU" or "HKEY_CURRENT_USER" => Registry.CurrentUser,
            "HKCR" or "HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
            "HKU" or "HKEY_USERS" => Registry.Users,
            _ => throw new ArgumentException($"Ruche inconnue : {hiveName}", nameof(keyPath)),
        };

        return hive.OpenSubKey(subKey, writable: false);
    }
}
