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
 * Tutoring schedule availability helpers.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class tutoring {
    /**
     * Check whether a teacher is available now (according to their tutoring schedule)
     * for a student who shares a visible course with them.
     *
     * @param int $teacherid
     * @param int $studentid
     * @return array With keys hasschedule (bool), available (bool), nextslot (string|null).
     */
    public static function check_availability($teacherid, $studentid) {
        global $DB;

        // Find visible courses where teacherid is teacher/editingteacher AND studentid is student.
        $teacherroles = array_keys(get_archetype_roles('teacher') + get_archetype_roles('editingteacher'));
        $studentroles = array_keys(get_archetype_roles('student'));

        if (empty($teacherroles) || empty($studentroles)) {
            return ['hasschedule' => false, 'available' => true, 'nextslot' => null];
        }

        [$trolesql, $troleparams] = $DB->get_in_or_equal($teacherroles, SQL_PARAMS_NAMED, 'trole');
        [$srolesql, $sroleparams] = $DB->get_in_or_equal($studentroles, SQL_PARAMS_NAMED, 'srole');

        // Visible courses where teacherid has a teacher role.
        $teachercourses = $DB->get_fieldset_sql(
            "SELECT DISTINCT ctx.instanceid
               FROM {role_assignments} ra
               JOIN {context} ctx ON ctx.id = ra.contextid AND ctx.contextlevel = :ctxlevel
               JOIN {course} c ON c.id = ctx.instanceid AND c.visible = 1
              WHERE ra.userid = :teacherid AND ra.roleid $trolesql",
            array_merge(['ctxlevel' => CONTEXT_COURSE, 'teacherid' => $teacherid], $troleparams)
        );

        if (empty($teachercourses)) {
            return ['hasschedule' => false, 'available' => true, 'nextslot' => null];
        }

        // From those, visible courses where studentid has a student role.
        [$coursesql, $courseparams] = $DB->get_in_or_equal($teachercourses, SQL_PARAMS_NAMED, 'course');
        $sharedcourses = $DB->get_fieldset_sql(
            "SELECT DISTINCT ctx.instanceid
               FROM {role_assignments} ra
               JOIN {context} ctx ON ctx.id = ra.contextid AND ctx.contextlevel = :ctxlevel
               JOIN {course} c ON c.id = ctx.instanceid AND c.visible = 1
              WHERE ra.userid = :studentid AND ra.roleid $srolesql AND ctx.instanceid $coursesql",
            array_merge(['ctxlevel' => CONTEXT_COURSE, 'studentid' => $studentid], $sroleparams, $courseparams)
        );

        if (empty($sharedcourses)) {
            return ['hasschedule' => false, 'available' => true, 'nextslot' => null];
        }

        // Get tutoring schedule slots for those courses.
        [$csql, $cparams] = $DB->get_in_or_equal($sharedcourses, SQL_PARAMS_NAMED, 'sc');
        $slots = $DB->get_records_select(
            'jitsi_tutoring_schedule',
            "userid = :teacherid AND courseid $csql",
            array_merge(['teacherid' => $teacherid], $cparams),
            'weekday ASC, timestart ASC'
        );

        if (empty($slots)) {
            return ['hasschedule' => false, 'available' => true, 'nextslot' => null];
        }

        // Get teacher's timezone and current time in that timezone.
        $teacher = $DB->get_record('user', ['id' => $teacherid], 'timezone');
        $teachertz = \core_date::normalise_timezone($teacher->timezone);
        $now = new \DateTime('now', new \DateTimeZone($teachertz));
        $currentweekday = (int)$now->format('w'); // 0=Sunday to 6=Saturday.
        $currentsecsofday = ((int)$now->format('H')) * 3600 + ((int)$now->format('i')) * 60 + (int)$now->format('s');

        // Check if we are currently within any slot.
        foreach ($slots as $slot) {
            $slotday = (int)$slot->weekday;
            $slotstart = (int)$slot->timestart;
            $slotend = (int)$slot->timeend;
            if ($slotday === $currentweekday && $currentsecsofday >= $slotstart && $currentsecsofday < $slotend) {
                return ['hasschedule' => true, 'available' => true, 'nextslot' => null];
            }
        }

        // Not available now — find next slot within the next 7 days.
        $nextslotstr = null;
        $weekdays = [
            0 => get_string('weekday0', 'mod_jitsi'),
            1 => get_string('weekday1', 'mod_jitsi'),
            2 => get_string('weekday2', 'mod_jitsi'),
            3 => get_string('weekday3', 'mod_jitsi'),
            4 => get_string('weekday4', 'mod_jitsi'),
            5 => get_string('weekday5', 'mod_jitsi'),
            6 => get_string('weekday6', 'mod_jitsi'),
        ];

        // Build candidate list: remaining slots today, then next 6 days.
        for ($dayoffset = 0; $dayoffset <= 6; $dayoffset++) {
            $checkday = ($currentweekday + $dayoffset) % 7;
            foreach ($slots as $slot) {
                if ((int)$slot->weekday !== $checkday) {
                    continue;
                }
                // If same day, only consider future slots.
                if ($dayoffset === 0 && (int)$slot->timestart <= $currentsecsofday) {
                    continue;
                }
                $h = intdiv((int)$slot->timestart, 3600);
                $m = intdiv(((int)$slot->timestart % 3600), 60);
                $nextslotstr = $weekdays[$checkday] . ' ' . sprintf('%02d:%02d', $h, $m);
                break 2;
            }
        }

        return ['hasschedule' => true, 'available' => false, 'nextslot' => $nextslotstr];
    }
}
