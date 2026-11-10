using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace ProcessVault.Desktop;

public partial class App : Application
{
    private const string PersonalizeKey = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

    private static readonly IReadOnlyDictionary<string, string> LightPalette = new Dictionary<string, string>
    {
        ["InkBrush"] = "#1B292D",
        ["MutedBrush"] = "#68777A",
        ["CanvasBrush"] = "#F1F4F2",
        ["SurfaceBrush"] = "#FFFFFF",
        ["ControlBrush"] = "#FFFFFF",
        ["InputBrush"] = "#FFFFFF",
        ["LineBrush"] = "#DCE4E0",
        ["GridHeaderBrush"] = "#EEF2EF",
        ["AlternateRowBrush"] = "#F7F9F8",
        ["AccentSurfaceBrush"] = "#E5F3EA",
        ["AccentInkBrush"] = "#24623A",
        ["OverlayBrush"] = "#C919272C",
    };

    private static readonly IReadOnlyDictionary<string, string> DarkPalette = new Dictionary<string, string>
    {
        ["InkBrush"] = "#E6EDF0",
        ["MutedBrush"] = "#A7B2B9",
        ["CanvasBrush"] = "#171A1D",
        ["SurfaceBrush"] = "#22272B",
        ["ControlBrush"] = "#2B3136",
        ["InputBrush"] = "#171A1D",
        ["LineBrush"] = "#3A444B",
        ["GridHeaderBrush"] = "#2B3136",
        ["AlternateRowBrush"] = "#252B30",
        ["AccentSurfaceBrush"] = "#1C3327",
        ["AccentInkBrush"] = "#A5D6B2",
        ["OverlayBrush"] = "#B9000000",
    };

    protected override void OnStartup(StartupEventArgs e)
    {
        ApplySystemTheme();
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
        base.OnExit(e);
    }

    private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (!Dispatcher.HasShutdownStarted)
            Dispatcher.BeginInvoke(ApplySystemTheme);
    }

    private void ApplySystemTheme()
    {
        var isLight = Convert.ToInt32(Registry.GetValue(PersonalizeKey, "AppsUseLightTheme", 1)) != 0;
        var palette = isLight ? LightPalette : DarkPalette;

        foreach (var (resourceKey, hexColor) in palette)
        {
            var color = (Color)ColorConverter.ConvertFromString(hexColor);
            Resources[resourceKey] = new SolidColorBrush(color);
        }
    }
}
