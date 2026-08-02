using Rempart.Core.Cli;
using static Rempart.Cli.CliHost;

namespace Rempart.Cli.Commands;

/// <summary>
/// What the tool answers when it is not told what to do: the usage text, and the
/// destination of every unrecognised command word.
///
/// <para>
/// The text is written out by hand, but the exit-code block is not: it is derived from
/// <c>ExitCodes</c>, because the hand-written line it replaced had omitted code 4 from
/// the day that code appeared, and nothing could have noticed.
/// </para>
/// </summary>
internal static class HelpCommand
{
    /// <summary>Ignores its arguments: the help has no options of its own.</summary>
    public static int Run(string[] args)
    {
        _ = args;
        return Print(Text);
    }

    /// <summary>
    /// The usage text, read by <c>CommandSurfaceTests</c> from this very file: a guard
    /// that runs on the Linux job, which does not compile this project.
    /// </summary>
    private static string Text =>
        $"""
        Rempart — audit de postes Windows

          Sans argument, ou avec « --help », « -h » ou « help », ce texte s'affiche.
          Tout autre premier mot — « -scan », « --json » — est refusé : l'outil ne
          fait alors rien, et le dit avec le code 6 plutôt qu'avec celui du succès.

          rempart scan [--json] [--report [dossier]] [--from <instantané>]
                       [--rules <dossier>] [--analyze-store]
                       [--virustotal-key <clé>] [--fetch-pac] [--probe-dns]
              Analyse la machine locale, ou rejoue un instantané hors-ligne.

              --report écrit rapport.html, rapport.md et rapport.json dans
              <dossier>/<machine>-<date>/ ; sans valeur, dans « reports/ » à côté
              du binaire — le rangement de la clé USB. Le HTML est autonome :
              un seul fichier, aucune ressource externe, thème clair/sombre.

              --analyze-store mesure l'espace récupérable du magasin de composants
              (WinSxS) par couche. Opt-in : la pile de maintenance de Windows met
              des dizaines de secondes à répondre et exige l'élévation. Rien n'est
              supprimé, jamais.

              Trois appels réseau, tous opt-in et jamais en rejeu :
              --virustotal-key (ou REMPART_VT_KEY) enrichit les constats signalés
              de leur réputation VirusTotal ; --fetch-pac récupère et analyse le
              script PAC d'un proxy signalé ; --probe-dns mesure la latence des
              résolveurs chiffrés (DoH/DoT) et recommande le plus rapide.

          rempart report --from <rapport.json> [--out <dossier>]
                         [--format html|markdown|json]
              Re-fabrique un rapport depuis le JSON d'un scan, sans rescanner.
              Le JSON est l'artefact complet — HTML et Markdown le résument.
              Écrit dans le dossier indiqué (par défaut le dossier courant) ;
              --format n'en produit qu'un seul. Ne demande pas Windows.

          rempart diff <avant.json> <après.json> [--report <dossier>]
          rempart diff <après.json> [--baseline <fichier>] [--report <dossier>]
              Compare deux rapports : ce qui a régressé, ce que l'audit ne voit
              plus, les constats apparus ou modifiés. Avec un seul argument, la
              comparaison se fait contre baseline.json posé à côté du binaire —
              la posture de référence que porte la clé.
              Les mouvements que le système cause lui-même sortent de l'écart de
              posture sans être tus : entrée RunOnce consommée, tâche supprimée
              après expiration, port de la plage dynamique renuméroté.
              --report écrit comparaison.html, .md et .json dans <dossier> ;
              sans valeur, dans le dossier courant.
              Ne demande pas Windows. Code de sortie 4 s'il y a une régression.

          rempart index [dossier] [--out <fichier>]
              Lit tous les rapport.json d'un dossier et écrit une page de parc,
              la plus basse d'abord. Par défaut « reports/ » à côté du binaire.
              Signale les rapports issus de catalogues différents : leurs
              pourcentages ne sont pas sur la même échelle.

          rempart drift [dossier] [--out <fichier>]
              Lit la série des rapport.json d'un dossier et écrit, par machine,
              la trajectoire : la pente du score, depuis quand un contrôle
              échoue, ceux qui retombent, et la date de la dernière capture.
              Ce que deux rapports comparés ne peuvent pas dire.
              Ne supprime rien : la fenêtre couverte et la place occupée sont
              dites, l'élagage reste un geste manuel.
              Ne demande pas Windows. Code de sortie 4 s'il reste une régression
              ouverte, 5 si la série s'est arrêtée ou si le dernier scan a laissé
              des contrôles inévaluables.

          rempart capture [--out <fichier>] [--raw] [--analyze-store]
              Enregistre l'état brut de la machine, rejouable en test.
              Anonymisé par défaut ; --raw conserve les identifiants.

          rempart explain [<ID>] [--rules <dossier>]
              Liste les contrôles, ou détaille une règle : justification,
              références, et ce que coûte sa correction.

          --rules <dossier>
              Charge des règles YAML supplémentaires, en plus des règles
              embarquées. Itérer sans recompiler, ou porter des contrôles
              propres à un parc. Les identifiants doivent rester uniques.
              À défaut d'option, un dossier « rules/ » posé à côté du binaire
              est chargé — le rangement de la clé. L'en-tête du scan le dit,
              et l'empreinte du catalogue change : jamais en silence.

          rempart synthesise --from <capture> --out <fichier>
                             [--profile hardened|defaults] [--name <nom>]
                             [--domain-joined] [--not-elevated] [--deny <fragment>]
                             [--compromised]
              Fabrique une fixture de test à partir d'une capture réelle.
              --compromised y plante des signes d'intrusion fabriqués — pilote
              non signé, autorun dans %TEMP%, port joignable, abonnement WMI,
              résolveur DNS détourné, extension chargée hors magasin, tâche
              planifiée non signée. Indépendant du profil : une machine durcie
              se fait compromettre aussi.

          rempart diagnose-wmi
              Vérifie que WMI répond. Destiné à la CI, contre le binaire AOT.

          rempart diagnose-tasks
              Vérifie que le planificateur de tâches répond. Même usage.

          rempart diagnose-drivers
              Vérifie que l'énumération des pilotes chargés répond, et que
              leurs chemins désignent des fichiers. Même usage : zéro pilote
              sur une machine allumée est une panne, jamais une réponse.

          rempart diagnose-processes
              Vérifie que l'énumération des processus répond, et qu'elle
              trouve le processus courant. Même usage.

          rempart diagnose-store [--raw]
              Vérifie que l'analyse du magasin de composants répond et que ses
              libellés sont toujours ceux que le lecteur attend. Exige
              l'élévation ; --raw montre la sortie brute de l'outil.

          rempart seal --dir <dossier> (--key <clé privée> | --check)
              Scelle la clé USB, ou vérifie qu'elle est restée ce qu'elle était.
              Le sceau est signé par la clé d'éditeur (ADR-002) : une simple
              liste d'empreintes posée à côté des fichiers qu'elle décrit ne
              protège de rien, qui modifie un fichier recalcule la ligne.
              Les rapports et le magasin de mise à jour en sont exclus : ils
              changent à l'usage normal. Un binaire qui se vérifie lui-même
              prouve peu — ce contrôle vaut lancé depuis une copie sûre.

          rempart keygen [--out <fichier>]
              Génère la paire de clés d'éditeur, pour signer les manifestes.
              À lancer sur une machine hors ligne — voir ADR-002. La clé privée
              est chiffrée par une phrase de passe, sans option contraire.

          rempart fetch-loldrivers [--out <fichier>]
              Télécharge la liste officielle LOLDrivers et la prépare à signer.
              L'outil va chercher la donnée ; toi seul la signes ensuite.

          rempart fetch-bloatware [--out <fichier>] [--judgement <fichier>]
              Joint les identifiants de la liste amont au jugement du dépôt, et
              prépare le catalogue à signer. Un identifiant sans note d'impact
              arrête la commande en le nommant : l'amont fournit les faits, les
              catégories et les notes s'écrivent ici.

          rempart sign --key <clé privée> --data <dossier> [--out <manifeste>]
                       [--kind rules|drivers] [--published <date ISO>]
              Signe un manifeste sur les jeux de données d'un dossier. À lancer
              hors ligne avec la clé privée, pendant de keygen. Le type est deviné
              à l'extension (.yaml = règles, sinon pilotes), ou imposé par --kind.

          rempart update (--from <manifeste> | --url <base>) [--apply] [--yes]
                         [--store <dossier>]
              Vérifie un manifeste signé et ses jeux de données, puis montre ce
              qui changerait. --from lit un fichier local (flux clé USB) ; --url
              télécharge <base>/manifest.json et ses jeux de données. Le transport
              n'est jamais de confiance : seule la signature l'est. Sans --apply,
              n'écrit rien ; avec, pose la mise à jour après confirmation (ou --yes).

          rempart version

        Codes de sortie
        {ExitCodes.HelpBlock}
        """;
}
