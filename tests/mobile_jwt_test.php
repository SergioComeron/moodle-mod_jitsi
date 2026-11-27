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

namespace mod_jitsi;

use mod_jitsi\external\get_session_state;
use mod_jitsi\local\session;
use mod_jitsi\output\mobile;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;

/**
 * The mobile session token and get_session_state must match the web session for every server type.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(get_session_state::class)]
#[CoversMethod(mobile::class, 'mobile_session_view')]
#[CoversMethod(session::class, 'room_name')]
#[CoversMethod(session::class, 'requires_jwt')]
#[CoversMethod(session::class, 'get_server')]
final class mobile_jwt_test extends \advanced_testcase {
    /** @var string|null Public key matching the JaaS private key of the test server. */
    protected $publickey = null;

    /**
     * Create and select a default server.
     *
     * @param int $type Server type.
     * @param array $fields Extra fields.
     * @return \stdClass Server record.
     */
    protected function set_server(int $type, array $fields = []): \stdClass {
        global $DB;
        $server = (object) ($fields + [
            'name' => 'Server ' . $type,
            'type' => $type,
            'domain' => 'jitsi.example.com',
            'appid' => '',
            'secret' => '',
            'eightbyeightappid' => '',
            'eightbyeightapikeyid' => '',
            'privatekey' => '',
            'timecreated' => time(),
            'timemodified' => time(),
        ]);
        $server->id = $DB->insert_record('jitsi_servers', $server);
        set_config('server', $server->id, 'mod_jitsi');
        return $server;
    }

    /**
     * Create a JaaS (type 2) server with a fresh RSA key pair.
     *
     * @return \stdClass Server record.
     */
    protected function set_jaas_server(): \stdClass {
        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($res, $privatekey);
        $this->publickey = openssl_pkey_get_details($res)['key'];
        return $this->set_server(2, [
            'domain' => '8x8.vc',
            'eightbyeightappid' => 'vpaas-magic-cookie-test',
            'eightbyeightapikeyid' => 'vpaas-magic-cookie-test/abc123',
            'privatekey' => $privatekey,
        ]);
    }

    /**
     * Create an activity and log in an enrolled student.
     *
     * @return array [course, jitsi, cm, user]
     */
    protected function create_activity(): array {
        $this->setAdminUser();
        $course = $this->getDataGenerator()->create_course(['shortname' => 'MOB2']);
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id, 'name' => 'Session']);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, 0, false, MUST_EXIST);
        $user = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $this->setUser($user);
        return [$course, $jitsi, $cm, $user];
    }

    /**
     * Decode a JWT into [header, payload, signed part, raw signature].
     *
     * @param string $jwt
     * @return array
     */
    protected function decode(string $jwt): array {
        [$h, $p, $s] = explode('.', $jwt);
        $dec = fn($x) => base64_decode(strtr($x, '-_', '+/'));
        return [json_decode($dec($h), true), json_decode($dec($p), true), $h . '.' . $p, $dec($s)];
    }

    /**
     * Call mobile_session_view and return its otherdata.
     *
     * @param int $cmid
     * @return array
     */
    protected function mobile_data(int $cmid): array {
        $result = mobile::mobile_session_view(['cmid' => $cmid, 'appisdesktop' => false]);
        return json_decode($result['otherdata'], true);
    }

    /**
     * Web token for the same user and activity, as session.php builds it.
     *
     * @param \stdClass $server
     * @param \stdClass $jitsi
     * @param \stdClass $course
     * @param \stdClass $cm
     * @param \stdClass $user
     * @return array build_token() result.
     */
    protected function web_token(\stdClass $server, \stdClass $jitsi, \stdClass $course, \stdClass $cm, \stdClass $user): array {
        global $CFG;
        $context = \context_module::instance($cm->id);
        $sessionnorm = local\room::normalize_session_name(local\room::for_activity($jitsi, $course));
        $avatar = get_config('mod_jitsi', 'showavatars') ? $CFG->wwwroot . '/user/pix.php/' . $user->id . '/f1.jpg' : null;
        $mail = get_config('mod_jitsi', 'sendemail') ? $user->email : null;
        return session::build_token($server, $context, $sessionnorm, false, 'member', $user->username, $avatar, $mail);
    }

    /**
     * On 8x8 JaaS the mobile token is the web RS256 token: API key kid, appid as sub, appid/room as room.
     */
    public function test_jaas_mobile_token_matches_web(): void {
        $this->resetAfterTest();
        set_config('id', 'username', 'mod_jitsi');
        $server = $this->set_jaas_server();
        [$course, $jitsi, $cm, $user] = $this->create_activity();

        $data = $this->mobile_data($cm->id);
        $web = $this->web_token($server, $jitsi, $course, $cm, $user);

        $this->assertArrayHasKey('jwt', $data, 'JaaS always needs a JWT');
        $this->assertStringStartsWith('jwt=', $data['jwt']);
        [$header, $payload, $signed, $signature] = $this->decode(substr($data['jwt'], 4));
        [$webheader, $webpayload] = $this->decode($web['jwt']);

        $this->assertSame('RS256', $header['alg']);
        $this->assertSame('vpaas-magic-cookie-test/abc123', $header['kid']);
        $this->assertSame($webheader, $header);
        $this->assertSame('vpaas-magic-cookie-test', $payload['sub']);
        $this->assertSame('chat', $payload['iss']);
        $this->assertSame('jitsi', $payload['aud']);
        $this->assertSame($webpayload['room'], $payload['room']);
        $this->assertSame($webpayload['context'], $payload['context']);
        $this->assertSame(1, openssl_verify($signed, $signature, $this->publickey, OPENSSL_ALGO_SHA256));

        $this->assertSame('8x8.vc', $data['jitsi_domain']);
        $this->assertSame($web['roomname'], $data['room']);
        $this->assertStringStartsWith('vpaas-magic-cookie-test/', $data['room']);
    }

    /**
     * On 8x8 JaaS get_session_state returns the JaaS room and requires a JWT.
     */
    public function test_jaas_session_state(): void {
        $this->resetAfterTest();
        $server = $this->set_jaas_server();
        [$course, $jitsi, $cm, $user] = $this->create_activity();

        $state = get_session_state::execute($cm->id);
        $data = $this->mobile_data($cm->id);

        $this->assertSame('8x8.vc', $state['domain']);
        $this->assertTrue($state['jwt_required']);
        $this->assertSame($this->web_token($server, $jitsi, $course, $cm, $user)['roomname'], $state['room']);
        $this->assertSame($data['room'], $state['room']);
        $this->assertStringNotContainsString('PRIVATE KEY', json_encode($state));
    }

    /**
     * On a self-hosted server the mobile token carries exactly the web claims and the server HMAC.
     */
    public function test_selfhosted_mobile_token_matches_web(): void {
        $this->resetAfterTest();
        set_config('id', 'username', 'mod_jitsi');
        set_config('showavatars', 1, 'mod_jitsi');
        $server = $this->set_server(1, ['appid' => 'myapp', 'secret' => 'topsecret', 'domain' => 'meet.example.org']);
        [$course, $jitsi, $cm, $user] = $this->create_activity();

        $data = $this->mobile_data($cm->id);
        $web = $this->web_token($server, $jitsi, $course, $cm, $user);
        [$header, $payload, $signed, $signature] = $this->decode(substr($data['jwt'], 4));
        [$webheader, $webpayload] = $this->decode($web['jwt']);

        $this->assertSame($webheader, $header);
        unset($payload['exp'], $webpayload['exp']);
        $this->assertSame($webpayload, $payload);
        $this->assertSame(hash_hmac('sha256', $signed, 'topsecret', true), $signature);

        $state = get_session_state::execute($cm->id);
        $this->assertSame('meet.example.org', $state['domain']);
        $this->assertSame($web['roomname'], $state['room']);
        $this->assertSame($data['room'], $state['room']);
        $this->assertTrue($state['jwt_required']);
    }

    /**
     * A self-hosted server without app id or secret signs nothing, and get_session_state says so.
     */
    public function test_selfhosted_without_secret_has_no_jwt(): void {
        $this->resetAfterTest();
        $this->set_server(1, ['appid' => 'myapp', 'secret' => '']);
        [$course, $jitsi, $cm] = $this->create_activity();

        $this->assertArrayNotHasKey('jwt', $this->mobile_data($cm->id));
        $this->assertFalse(get_session_state::execute($cm->id)['jwt_required']);
    }

    /**
     * Without a configured server the app uses meet.jit.si and no token.
     */
    public function test_no_server_uses_public_default(): void {
        $this->resetAfterTest();
        set_config('server', 0, 'mod_jitsi');
        [$course, $jitsi, $cm] = $this->create_activity();

        $data = $this->mobile_data($cm->id);
        $state = get_session_state::execute($cm->id);

        $this->assertArrayNotHasKey('jwt', $data);
        $this->assertSame('meet.jit.si', $data['jitsi_domain']);
        $this->assertSame('meet.jit.si', $state['domain']);
        $this->assertFalse($state['jwt_required']);
        $this->assertSame($data['room'], $state['room']);
    }

    /**
     * requires_jwt and room_name follow build_token for each server type.
     */
    public function test_helpers_follow_build_token(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $context = \context_system::instance();
        $servers = [
            (object) ['type' => 0, 'appid' => '', 'secret' => '', 'domain' => 'meet.jit.si'],
            (object) ['type' => 1, 'appid' => 'a', 'secret' => 's', 'domain' => 'x.org'],
            (object) ['type' => 1, 'appid' => 'a', 'secret' => '', 'domain' => 'x.org'],
            (object) ['type' => 3, 'appid' => 'a', 'secret' => 's', 'domain' => 'x.org'],
        ];
        foreach ($servers as $server) {
            $server->eightbyeightappid = '';
            $server->eightbyeightapikeyid = '';
            $server->privatekey = '';
            $token = session::build_token($server, $context, 'Room-1', false, 'member', 'Ann', null, null);
            $this->assertSame($token['jwt'] !== null, session::requires_jwt($server), 'type ' . $server->type);
            $this->assertSame($token['roomname'], session::room_name($server, 'Room-1'));
        }
    }
}
