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

use mod_jitsi\local\vertex_ai;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Unit tests for the Vertex AI helper.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(vertex_ai::class)]
final class vertex_ai_test extends \advanced_testcase {
    /**
     * Build a jitsi_source_record-like object.
     *
     * @param string $link Recording link
     * @param int $type Source type
     * @param int $timeexpires Expiry timestamp
     * @return \stdClass
     */
    protected function make_source(string $link, int $type = 1, int $timeexpires = 0): \stdClass {
        return (object)[
            'link'        => $link,
            'type'        => $type,
            'timeexpires' => $timeexpires,
        ];
    }

    /**
     * GCS recordings are supported regardless of source type.
     */
    public function test_supports_gcs(): void {
        $this->assertTrue(vertex_ai::supports(
            $this->make_source('https://storage.googleapis.com/bucket/rec.mp4', 0)
        ));
    }

    /**
     * Type-1 external https links are supported while not expired.
     */
    public function test_supports_external_link(): void {
        $this->assertTrue(vertex_ai::supports(
            $this->make_source('https://recordings.8x8.vc/room/rec.mp4?token=abc', 1, time() + DAYSECS)
        ));
        $this->assertTrue(vertex_ai::supports(
            $this->make_source('https://example.com/rec.webm', 1, 0)
        ));
    }

    /**
     * Expired links, http links and YouTube type-0 records are rejected.
     */
    public function test_supports_rejections(): void {
        // Expired external link.
        $this->assertFalse(vertex_ai::supports(
            $this->make_source('https://recordings.8x8.vc/rec.mp4', 1, time() - 10)
        ));
        // Plain http (offline Jibri VM) link.
        $this->assertFalse(vertex_ai::supports(
            $this->make_source('http://10.0.0.2/recordings/rec.mp4', 1)
        ));
        // YouTube record (type 0, link is a video id).
        $this->assertFalse(vertex_ai::supports($this->make_source('dQw4w9WgXcQ', 0)));
    }

    /**
     * GCS links are converted to gs:// URIs.
     */
    public function test_media_for_gcs(): void {
        $media = vertex_ai::media_for(
            $this->make_source('https://storage.googleapis.com/mybucket/dir/rec.mp4', 1)
        );
        $this->assertSame('gs://mybucket/dir/rec.mp4', $media['fileuri']);
        $this->assertSame('video/mp4', $media['mimetype']);
    }

    /**
     * External links are passed through with a guessed MIME type; Dropbox host is swapped.
     */
    public function test_media_for_external(): void {
        $media = vertex_ai::media_for(
            $this->make_source('https://recordings.8x8.vc/room/rec.webm?token=abc', 1)
        );
        $this->assertSame('https://recordings.8x8.vc/room/rec.webm?token=abc', $media['fileuri']);
        $this->assertSame('video/webm', $media['mimetype']);

        $media = vertex_ai::media_for(
            $this->make_source('https://www.dropbox.com/scl/fi/xyz/rec.mp4?rlkey=k&dl=0', 1)
        );
        $this->assertSame('https://dl.dropboxusercontent.com/scl/fi/xyz/rec.mp4?rlkey=k&dl=0', $media['fileuri']);
        $this->assertSame('video/mp4', $media['mimetype']);

        $this->assertNull(vertex_ai::media_for($this->make_source('dQw4w9WgXcQ', 0)));
    }

    /**
     * MIME type guessing falls back to video/mp4 for unknown extensions.
     */
    public function test_guess_mimetype(): void {
        $this->assertSame('video/mp4', vertex_ai::guess_mimetype('https://x.com/a.mp4'));
        $this->assertSame('video/webm', vertex_ai::guess_mimetype('https://x.com/a.webm?q=1'));
        $this->assertSame('audio/mpeg', vertex_ai::guess_mimetype('https://x.com/a.mp3'));
        $this->assertSame('video/mp4', vertex_ai::guess_mimetype('https://x.com/download?id=9'));
    }

    /**
     * Video URL extraction from HTML player pages (e.g. 8x8/JaaS recording links).
     */
    public function test_extract_video_url(): void {
        // 8x8-style player page: pre-authenticated object storage URL in the markup.
        $html = '<html><body><script>var src = '
            . '"https://objectstorage.uk-london-1.oraclecloud.com/p/TOK/n/ns/b/bucket/o/rec.mp4";'
            . '</script></body></html>';
        $this->assertSame(
            'https://objectstorage.uk-london-1.oraclecloud.com/p/TOK/n/ns/b/bucket/o/rec.mp4',
            vertex_ai::extract_video_url($html)
        );

        // Standard video/source tags win, with HTML entities decoded.
        $html = '<video controls><source src="https://cdn.example.com/rec.mp4?a=1&amp;b=2" type="video/mp4"></video>';
        $this->assertSame('https://cdn.example.com/rec.mp4?a=1&b=2', vertex_ai::extract_video_url($html));

        // Bare mp4 URL anywhere in the page.
        $html = '<a href="https://files.example.com/download/rec.webm?tok=x">download</a>';
        $this->assertSame('https://files.example.com/download/rec.webm?tok=x', vertex_ai::extract_video_url($html));

        // Nothing that looks like a video.
        $this->assertNull(vertex_ai::extract_video_url('<html><body>No video here</body></html>'));
    }

    /**
     * Pending-task detection matches the exact sourcerecordid in the queue.
     */
    public function test_has_pending_task(): void {
        $this->resetAfterTest(true);

        $task = new \mod_jitsi\task\generate_ai_summary();
        $task->set_custom_data(['sourcerecordid' => 12, 'lang' => 'es']);
        \core\task\manager::queue_adhoc_task($task);

        $this->assertTrue(vertex_ai::has_pending_task(\mod_jitsi\task\generate_ai_summary::class, 12));
        // Different id, prefix of a queued id, and different task class must not match.
        $this->assertFalse(vertex_ai::has_pending_task(\mod_jitsi\task\generate_ai_summary::class, 1));
        $this->assertFalse(vertex_ai::has_pending_task(\mod_jitsi\task\generate_ai_summary::class, 123));
        $this->assertFalse(vertex_ai::has_pending_task(\mod_jitsi\task\generate_ai_quiz::class, 12));
    }

    /**
     * Project resolution: bucket server first, then the global gcp_project setting.
     */
    public function test_project_for(): void {
        global $DB;
        $this->resetAfterTest(true);

        $source = $this->make_source('https://recordings.8x8.vc/rec.mp4', 1, time() + DAYSECS);
        $this->assertSame('', vertex_ai::project_for($source));

        set_config('gcp_project', 'my-global-project', 'mod_jitsi');
        $this->assertSame('my-global-project', vertex_ai::project_for($source));

        // A GCS recording resolves via its bucket's server, overriding the global setting.
        $DB->insert_record('jitsi_servers', (object)[
            'name'         => 'GCP server',
            'type'         => 3,
            'timecreated'  => time(),
            'timemodified' => time(),
            'gcs_enabled'  => 1,
            'gcs_bucket'   => 'mybucket',
            'gcpproject'   => 'server-project',
        ]);
        $gcssource = $this->make_source('https://storage.googleapis.com/mybucket/rec.mp4', 1);
        $this->assertSame('server-project', vertex_ai::project_for($gcssource));
    }
}
