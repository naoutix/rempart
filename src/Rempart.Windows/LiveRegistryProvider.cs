using System.Security;
using Microsoft.Win32;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Real implementation over the Windows registry. The only layer of the project that
/// knows <c>Microsoft.Win32</c> — everything else works against
/// <see cref="IRegistryProvider"/>.
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

    public RegistryValueList ListValues(string keyPath)
    {
        var values = new Dictionary<string, RegistryValue>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var key = OpenKey(keyPath);
            if (key is null)
            {
                return RegistryValueList.NotFound;
            }

            foreach (var name in key.GetValueNames())
            {
                var raw = key.GetValue(name);
                if (raw is not null)
                {
                    values[name] = Convert(key.GetValueKind(name), raw);
                }
            }
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            // A denial still returns rather than throwing — enumeration of the other
            // locations must continue — but it returns a *refusal* and no longer an empty
            // listing. Those were the same value for three milestones, and a denial laid on
            // a Run key therefore read as « aucun démarrage automatique » (REV-11).
            return RegistryValueList.AccessDenied;
        }

        return RegistryValueList.Found(values);
    }

    public RegistrySubKeyList ListSubKeys(string keyPath)
    {
        try
        {
            using var key = OpenKey(keyPath);
            return key is null
                ? RegistrySubKeyList.NotFound
                : RegistrySubKeyList.Found(key.GetSubKeyNames());
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            // As for values: the other locations must still be enumerated, and the refusal
            // travels with the answer instead of being flattened into it.
            return RegistrySubKeyList.AccessDenied;
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
