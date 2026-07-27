using Rempart.Core.Updates;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Generates the key pair that will sign update manifests.
///
/// <para>
/// Run it on an offline machine — a disposable VM is enough when that is all you
/// have (ADR-002, D16). This is precisely the kind of use the standalone executable
/// deliverable exists for: copy <c>rempart.exe</c> onto a USB stick, generate
/// there, nothing to install.
/// </para>
///
/// <para>
/// The private key is never written in cleartext and no option exists to do so. A
/// removable drive gets lost; the passphrase is then what separates a lost key
/// from a compromised one.
/// </para>
/// </summary>
internal static class KeygenCommand
{
    public static int Run(string[] args)
    {
        var path = OptionValue(args, "--out") ?? "cle-privee-rempart.txt";

        if (File.Exists(path))
        {
            // Overwriting an existing private key destroys it beyond recovery: there is
            // no copy anywhere else, which is the whole point of the scheme.
            Console.Error.WriteLine($"{path} existe déjà. Refus d'écraser une clé privée.");
            return 1;
        }

        if (Console.IsInputRedirected)
        {
            // Without a console, the passphrase would come from a pipe — hence from a
            // history, a script, or a log. Refuse rather than produce a key whose
            // protection is already known to someone else.
            Console.Error.WriteLine(
                "Cette commande exige une console interactive : la phrase de passe ne doit " +
                "pas transiter par un tube ni par un argument.");
            return 1;
        }

        Console.WriteLine("Phrase de passe (12 caractères minimum, non affichée) :");
        var passphrase = ReadHidden();

        Console.WriteLine("Confirmer :");
        if (!string.Equals(passphrase, ReadHidden(), StringComparison.Ordinal))
        {
            Console.Error.WriteLine("Les deux saisies diffèrent. Rien n'a été écrit.");
            return 1;
        }

        PublisherKeyPair pair;
        try
        {
            pair = PublisherKey.Generate(passphrase);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        // Immediate read-back: a key that cannot be reopened must not be discovered
        // on publication day, on a machine that will have been destroyed by then.
        if (PublisherKey.ReadPublicKeyOf(pair.EncryptedPrivateKey, passphrase) != pair.PublicKey)
        {
            Console.Error.WriteLine("La clé générée ne se relit pas. Rien n'a été écrit.");
            return 1;
        }

        File.WriteAllText(path, pair.EncryptedPrivateKey);

        Console.WriteLine();
        Console.WriteLine($"Clé privée chiffrée écrite dans {path}.");
        Console.WriteLine("  Elle ne doit pas revenir sur la machine de développement.");
        Console.WriteLine("  La phrase de passe ne voyage pas sur le même support.");
        Console.WriteLine();
        Console.WriteLine("À reporter dans ManifestVerifier, publiables l'une comme l'autre :");
        Console.WriteLine();
        Console.WriteLine($"  empreinte     {pair.KeyId}");
        Console.WriteLine($"  clé publique  {pair.PublicKey}");
        Console.WriteLine();
        Console.WriteLine("Sauvegarde papier de la clé privée chiffrée — elle tient en une ligne,");
        Console.WriteLine("et c'est la meilleure protection contre la perte du support :");
        Console.WriteLine();
        Console.WriteLine($"  {pair.EncryptedPrivateKey}");

        return 0;
    }
}
