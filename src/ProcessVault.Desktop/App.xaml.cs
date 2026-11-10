using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace ProcessVault.Desktop;

public partial class App : Application
{
    private const string PersonalizeKey = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

    private static readonly IReadOnlyDictionary<string, string> LightPalette = new Dictionary<string, string>
    {
        ["InkBrush"] = "#202123",
        ["MutedBrush"] = "#6B6F76",
        ["CanvasBrush"] = "#FFFFFF",
        ["SurfaceBrush"] = "#FFFFFF",
        ["ControlBrush"] = "#F7F7F8",
        ["InputBrush"] = "#F7F7F8",
        ["LineBrush"] = "#E5E5E6",
        ["GridHeaderBrush"] = "#F1F1F2",
        ["AlternateRowBrush"] = "#F7F7F8",
        ["AccentSurfaceBrush"] = "#E7F0FF",
        ["AccentInkBrush"] = "#2458A6",
        ["OverlayBrush"] = "#C919272C",
    };

    private static readonly IReadOnlyDictionary<string, string> DarkPalette = new Dictionary<string, string>
    {
        ["InkBrush"] = "#ECECEC",
        ["MutedBrush"] = "#A0A0A0",
        ["CanvasBrush"] = "#171717",
        ["SurfaceBrush"] = "#1F1F1F",
        ["ControlBrush"] = "#2F2F2F",
        ["InputBrush"] = "#2F2F2F",
        ["LineBrush"] = "#393939",
        ["GridHeaderBrush"] = "#272727",
        ["AlternateRowBrush"] = "#222222",
        ["AccentSurfaceBrush"] = "#1E3A5F",
        ["AccentInkBrush"] = "#C2DCFF",
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
