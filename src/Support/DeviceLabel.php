<?php

namespace Uzairports\Uzairid\Support;

use Illuminate\Support\Str;

/**
 * A short name for the device behind a user agent, such as "Chrome — Windows".
 *
 * A guess, for display only; never decide anything on it.
 */
final class DeviceLabel
{
    /**
     * Browser tokens, most specific first: Chrome names itself Safari too, and
     * Edge names itself both, so the more specific token has to win.
     *
     * @var array<string, string>
     */
    private const array BROWSERS = [
        'Vivaldi' => 'Vivaldi',
        'Brave' => 'Brave',
        'Edg' => 'Edge',
        'OPR' => 'Opera',
        'YaBrowser' => 'Yandex',
        'SamsungBrowser' => 'Samsung Internet',
        'DuckDuckGo' => 'DuckDuckGo',
        'MiuiBrowser' => 'Miui Browser',
        'UCBrowser' => 'UC Browser',
        '; wv' => 'WebView',
        'WebView' => 'WebView',
        'Firefox' => 'Firefox',
        'Chrome' => 'Chrome',
        'Safari' => 'Safari',
    ];

    /**
     * @var array<string, string>
     */
    private const array PLATFORMS = [
        'Android' => 'Android',
        'iPhone' => 'iPhone',
        'iPad' => 'iPad',
        'Windows' => 'Windows',
        'Macintosh' => 'macOS',
        'CrOS' => 'ChromeOS',
        'Linux' => 'Linux',
    ];

    /**
     * The label for a user agent; an unrecognizable one is handed back as it
     * came (shortened), and none at all is "unknown device".
     */
    public static function for(?string $userAgent): string
    {
        $agent = (string) $userAgent;

        if ($agent === '') {
            return __('uzairid::messages.unknown_device');
        }

        $browser = self::firstMatch($agent, self::BROWSERS);
        $platform = self::firstMatch($agent, self::PLATFORMS);

        if ($browser === null && $platform === null) {
            return Str::limit($agent, 40);
        }

        return trim(($browser ?? '').' — '.($platform ?? ''), ' —');
    }

    /**
     * @param  array<string, string>  $needles
     */
    private static function firstMatch(string $agent, array $needles): ?string
    {
        foreach ($needles as $needle => $label) {
            if (str_contains($agent, $needle)) {
                return $label;
            }
        }

        return null;
    }
}
