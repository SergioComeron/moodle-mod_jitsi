<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace mod_jitsi\local;

/**
 * Signed presence tokens for the presence web services.
 *
 * The session page issues a token once it has validated access to the session (login and
 * mod/jitsi:view for course users, a valid invitation token for guests). The presence web
 * services, which must stay reachable without login for invited guests, only accept writes
 * that carry a valid token for the same activity and the same per-tab session hash.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class presence_token {
    /** @var int Token lifetime in seconds. */
    const TTL = 43200;

    /** @var int Maximum length of a guest display name. */
    const GUESTNAME_MAXLENGTH = 100;

    /** @var int Length of the server-generated per-tab session hash. */
    const SESSIONHASH_LENGTH = 32;

    /**
     * Return the site secret used to sign presence tokens, generating it on first use.
     *
     * @return string
     */
    private static function secret(): string {
        $secret = (string) get_config('mod_jitsi', 'presencesecret');
        if (strlen($secret) < 32) {
            $secret = random_string(64);
            set_config('presencesecret', $secret, 'mod_jitsi');
        }
        return $secret;
    }

    /**
     * Normalise a guest display name: plain text, trimmed and length-limited.
     *
     * @param string $name Raw name.
     * @return string
     */
    public static function clean_guestname(string $name): string {
        $name = trim(clean_param($name, PARAM_TEXT));
        return \core_text::substr($name, 0, self::GUESTNAME_MAXLENGTH);
    }

    /**
     * Sign a payload.
     *
     * @param string $data Encoded payload.
     * @return string Hex HMAC.
     */
    private static function sign(string $data): string {
        return hash_hmac('sha256', 'mod_jitsi_presence|' . $data, self::secret());
    }

    /**
     * Issue a presence token. Call only after access to the session has been validated.
     *
     * @param int $jitsiid Jitsi activity instance id.
     * @param int $userid Moodle user id, or 0 for guests.
     * @param string $guestname Display name for guests (ignored when $userid > 0).
     * @param int|null $now Current time, for tests.
     * @return array With keys token and sessionhash.
     */
    public static function issue(int $jitsiid, int $userid, string $guestname = '', ?int $now = null): array {
        $now = $now ?? time();
        $sessionhash = random_string(self::SESSIONHASH_LENGTH);
        $payload = [
            'j' => $jitsiid,
            'u' => $userid,
            'h' => $sessionhash,
            'g' => $userid > 0 ? '' : self::clean_guestname($guestname),
            'e' => $now + self::TTL,
        ];
        $data = util::base64url_encode(json_encode($payload));
        return ['token' => $data . '.' . self::sign($data), 'sessionhash' => $sessionhash];
    }

    /**
     * Verify a presence token for a given activity and session hash.
     *
     * @param string $token Token as issued by issue().
     * @param int $jitsiid Jitsi activity instance id the call targets.
     * @param string $sessionhash Session hash the call targets.
     * @return \stdClass Payload with userid and guestname.
     * @throws \moodle_exception If the token is invalid, expired or does not match.
     */
    public static function verify(string $token, int $jitsiid, string $sessionhash): \stdClass {
        global $USER;
        $parts = explode('.', $token);
        if (count($parts) !== 2 || $parts[0] === '' || !hash_equals(self::sign($parts[0]), $parts[1])) {
            throw new \moodle_exception('invalidaccess', 'error');
        }
        $payload = json_decode((string) util::base64url_decode($parts[0]));
        if (
            !is_object($payload) ||
            !isset($payload->j, $payload->u, $payload->h, $payload->g, $payload->e) ||
            (int) $payload->e < time() ||
            (int) $payload->j !== $jitsiid ||
            !hash_equals((string) $payload->h, $sessionhash)
        ) {
            throw new \moodle_exception('invalidaccess', 'error');
        }
        $userid = (int) $payload->u;
        // A token issued to a Moodle user is only valid in that user's session.
        if ($userid > 0 && (!isloggedin() || isguestuser() || (int) $USER->id !== $userid)) {
            throw new \moodle_exception('invalidaccess', 'error');
        }
        return (object) [
            'userid' => $userid,
            'guestname' => $userid > 0 ? '' : self::clean_guestname((string) $payload->g),
        ];
    }
}
