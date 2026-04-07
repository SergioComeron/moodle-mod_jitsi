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

/**
 * Ad-hoc task to generate a Moodle true/false quiz from a GCS recording via Vertex AI.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace mod_jitsi\task;

defined('MOODLE_INTERNAL') || die();

/**
 * Ad-hoc task: generate a true/false quiz in Moodle from a GCS recording using Gemini.
 *
 * Custom data expected:
 *   - sourcerecordid (int): ID of the jitsi_source_record row
 *   - cmid (int): course module ID of the jitsi activity
 *   - lang (string): language code for questions
 *
 * @package mod_jitsi
 */
class generate_ai_quiz extends \core\task\adhoc_task {
    /**
     * Returns the component that owns this task.
     */
    public function get_component(): string {
        return 'mod_jitsi';
    }

    /**
     * Execute the task: generate questions via Gemini and create a Moodle quiz.
     */
    public function execute(): void {
        global $CFG, $DB;

        require_once($CFG->dirroot . '/course/lib.php');
        require_once($CFG->dirroot . '/lib/questionlib.php');

        $data = $this->get_custom_data();
        if (empty($data->sourcerecordid) || empty($data->cmid)) {
            mtrace('generate_ai_quiz: missing sourcerecordid or cmid in custom data');
            return;
        }

        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => (int)$data->sourcerecordid]);
        if (!$sourcerecord) {
            mtrace("generate_ai_quiz: source record {$data->sourcerecordid} not found");
            return;
        }

        if (!preg_match('/^https:\/\/storage\.googleapis\.com\/([^\/]+)\/(.+)$/', $sourcerecord->link, $m)) {
            mtrace("generate_ai_quiz: not a GCS URL: {$sourcerecord->link}");
            $DB->set_field('jitsi_source_record', 'ai_quiz_id', -1, ['id' => $sourcerecord->id]);
            return;
        }

        $bucketname = $m[1];
        $objectname = $m[2];
        $gsuri = "gs://{$bucketname}/{$objectname}";

        $server = $DB->get_record('jitsi_servers', ['gcs_bucket' => $bucketname, 'gcs_enabled' => 1]);
        if (!$server || empty($server->gcpproject)) {
            mtrace("generate_ai_quiz: could not find GCP project for bucket {$bucketname}");
            $DB->set_field('jitsi_source_record', 'ai_quiz_id', -1, ['id' => $sourcerecord->id]);
            return;
        }

        // Load Google API.
        $autoloaders = [
            $CFG->dirroot . '/mod/jitsi/api/vendor/autoload.php',
            $CFG->dirroot . '/mod/jitsi/vendor/autoload.php',
            $CFG->dirroot . '/vendor/autoload.php',
        ];
        foreach ($autoloaders as $autoload) {
            if (file_exists($autoload)) {
                require_once($autoload);
                break;
            }
        }

        if (!class_exists('Google\\Client')) {
            mtrace('generate_ai_quiz: Google API client not available');
            $DB->set_field('jitsi_source_record', 'ai_quiz_id', -1, ['id' => $sourcerecord->id]);
            return;
        }

        $numquestions = (int)(get_config('mod_jitsi', 'aiquizquestions') ?: 10);
        $numquestions = max(3, min(20, $numquestions));
        $lang = !empty($data->lang) ? $data->lang : 'en';

        try {
            // Get Vertex AI access token.
            $client = new \Google\Client();
            $client->addScope('https://www.googleapis.com/auth/cloud-platform');
            $fs = get_file_storage();
            $ctx = \context_system::instance();
            $files = $fs->get_area_files(
                $ctx->id,
                'mod_jitsi',
                'gcpserviceaccountjson',
                0,
                'itemid, filepath, filename',
                false
            );
            if (!empty($files)) {
                $file = reset($files);
                $key = json_decode($file->get_content(), true);
                if (is_array($key)) {
                    $client->setAuthConfig($key);
                } else {
                    $client->useApplicationDefaultCredentials();
                }
            } else {
                $client->useApplicationDefaultCredentials();
            }
            $accesstoken = $client->fetchAccessTokenWithAssertion();
            if (empty($accesstoken['access_token'])) {
                throw new \Exception('Could not obtain Vertex AI access token');
            }

            $token = $accesstoken['access_token'];
            $project = $server->gcpproject;
            $location = 'us-central1';
            $model = 'gemini-2.5-flash';
            $endpoint = "https://{$location}-aiplatform.googleapis.com/v1/projects/{$project}"
                . "/locations/{$location}/publishers/google/models/{$model}:generateContent";

            $prompt = "Analyze this video recording of an online class and generate exactly {$numquestions} "
                . "true/false questions to assess student comprehension. "
                . "Write the questions in the following language: {$lang}. "
                . "Return ONLY a valid JSON array. Each element must have exactly two fields: "
                . "\"question\" (string with the question text) and \"correct\" (boolean, the correct answer). "
                . "Do not include any explanation, markdown, or text outside the JSON array.";

            $body = json_encode([
                'contents' => [
                    [
                        'role' => 'user',
                        'parts' => [
                            ['text' => $prompt],
                            [
                                'fileData' => [
                                    'mimeType' => 'video/mp4',
                                    'fileUri' => $gsuri,
                                ],
                            ],
                        ],
                    ],
                ],
                'generationConfig' => [
                    'temperature' => 0.3,
                    'maxOutputTokens' => 2048,
                ],
            ]);

            $ch = curl_init($endpoint);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Authorization: Bearer ' . $token,
                'Content-Type: application/json',
            ]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 120);
            $response = curl_exec($ch);
            $curlerror = curl_error($ch);
            $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($response === false || $httpcode === 0) {
                throw new \Exception("Curl error: {$curlerror}");
            }
            if ($httpcode !== 200) {
                throw new \Exception("Vertex AI returned HTTP {$httpcode}: {$response}");
            }

            $result = json_decode($response, true);
            $rawtext = $result['candidates'][0]['content']['parts'][0]['text'] ?? '';
            if (empty($rawtext)) {
                throw new \Exception('Empty response from Vertex AI');
            }

            // Strip markdown code fences if present.
            $rawtext = preg_replace('/^```(?:json)?\s*/m', '', $rawtext);
            $rawtext = preg_replace('/```\s*$/m', '', $rawtext);
            $questions = json_decode(trim($rawtext), true);
            if (!is_array($questions) || empty($questions)) {
                throw new \Exception('Could not parse questions JSON: ' . $rawtext);
            }

            // Find the jitsi activity and course from the cmid.
            $cm = get_coursemodule_from_id('jitsi', (int)$data->cmid, 0, false, MUST_EXIST);
            $course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);
            $jitsirecord = $DB->get_record('jitsi_record', ['source' => $sourcerecord->id]);
            $jitsi = $jitsirecord ? $DB->get_record('jitsi', ['id' => $jitsirecord->jitsi]) : null;
            $recordname = $jitsi ? $jitsi->name : get_string('aiquiz', 'jitsi');

            $coursecontext = \context_course::instance($course->id);
            $adminid = get_admin()->id;

            // Get or create a question category for this course.
            $category = $DB->get_record('question_categories', [
                'contextid' => $coursecontext->id,
                'parent' => 0,
            ]);
            if (!$category) {
                $category = new \stdClass();
                $category->name = 'Default for ' . $course->shortname;
                $category->contextid = $coursecontext->id;
                $category->info = '';
                $category->infoformat = FORMAT_PLAIN;
                $category->parent = 0;
                $category->sortorder = 999;
                $category->stamp = make_unique_id_code();
                $category->id = $DB->insert_record('question_categories', $category);
            }

            // Moodle 4.x uses 'question_bank_entry' (singular), Moodle 5.x renamed it to 'question_bank_entries'.
            $qbetable = $DB->get_manager()->table_exists('question_bank_entries')
                ? 'question_bank_entries' : 'question_bank_entry';
            // In Moodle 5.x, question.category was removed (stored in question_bank_entries only).
            $questionhascategory = array_key_exists('category', $DB->get_columns('question'));
            // In Moodle 5.x, quiz_slots no longer has questionbankentryid; links via question_references.
            $slotshasqbeid = array_key_exists('questionbankentryid', $DB->get_columns('quiz_slots'));
            $hasquestionrefs = $DB->get_manager()->table_exists('question_references');

            // Create each true/false question.
            $questionids = [];
            $qbeids = [];
            foreach ($questions as $q) {
                if (empty($q['question']) || !isset($q['correct'])) {
                    continue;
                }

                // question_bank_entry / question_bank_entries.
                $qbe = new \stdClass();
                $qbe->questioncategoryid = $category->id;
                $qbe->idnumber = null;
                $qbe->ownerid = $adminid;
                $qbeid = $DB->insert_record($qbetable, $qbe);

                // question.
                $question = new \stdClass();
                if ($questionhascategory) {
                    $question->category = $category->id;
                }
                $question->name = \core_text::substr($q['question'], 0, 255);
                $question->questiontext = $q['question'];
                $question->questiontextformat = FORMAT_HTML;
                $question->generalfeedback = '';
                $question->generalfeedbackformat = FORMAT_HTML;
                $question->defaultmark = 1;
                $question->penalty = 1;
                $question->qtype = 'truefalse';
                $question->length = 1;
                $question->stamp = make_unique_id_code();
                $question->timecreated = time();
                $question->timemodified = time();
                $question->createdby = $adminid;
                $question->modifiedby = $adminid;
                $questionid = $DB->insert_record('question', $question);

                // question_versions.
                $qv = new \stdClass();
                $qv->questionbankentryid = $qbeid;
                $qv->version = 1;
                $qv->questionid = $questionid;
                $qv->status = 'ready';
                $DB->insert_record('question_versions', $qv);

                // Answers: true and false.
                $trueans = new \stdClass();
                $trueans->question = $questionid;
                $trueans->answer = 'True';
                $trueans->answerformat = FORMAT_PLAIN;
                $trueans->fraction = $q['correct'] ? 1 : 0;
                $trueans->feedback = '';
                $trueans->feedbackformat = FORMAT_HTML;
                $trueansid = $DB->insert_record('question_answers', $trueans);

                $falseans = new \stdClass();
                $falseans->question = $questionid;
                $falseans->answer = 'False';
                $falseans->answerformat = FORMAT_PLAIN;
                $falseans->fraction = $q['correct'] ? 0 : 1;
                $falseans->feedback = '';
                $falseans->feedbackformat = FORMAT_HTML;
                $falseansid = $DB->insert_record('question_answers', $falseans);

                // question_truefalse.
                $tf = new \stdClass();
                $tf->question = $questionid;
                $tf->trueanswer = $trueansid;
                $tf->falseanswer = $falseansid;
                $DB->insert_record('question_truefalse', $tf);

                $questionids[] = $questionid;
                $qbeids[] = $qbeid;
            }

            if (empty($questionids)) {
                throw new \Exception('No valid questions were generated');
            }

            // Create the quiz activity.
            $quizmodule = $DB->get_record('modules', ['name' => 'quiz'], '*', MUST_EXIST);

            $quiz = new \stdClass();
            $quiz->course = $course->id;
            $quiz->name = get_string('aiquiz', 'jitsi') . ': ' . $recordname;
            $quiz->intro = '';
            $quiz->introformat = FORMAT_HTML;
            $quiz->timeopen = 0;
            $quiz->timeclose = 0;
            $quiz->timelimit = 0;
            $quiz->overduehandling = 'autosubmit';
            $quiz->graceperiod = 0;
            $quiz->preferredbehaviour = 'deferredfeedback';
            $quiz->canredoquestions = 0;
            $quiz->attempts = 0;
            $quiz->attemptonlast = 0;
            $quiz->grademethod = 1;
            $quiz->decimalpoints = 2;
            $quiz->questiondecimalpoints = -1;
            $quiz->reviewattempt = 69904;
            $quiz->reviewcorrectness = 4368;
            $quiz->reviewmarks = 4368;
            $quiz->reviewspecificfeedback = 4368;
            $quiz->reviewgeneralfeedback = 4368;
            $quiz->reviewrightanswer = 4368;
            $quiz->reviewoverallfeedback = 4368;
            $quiz->questionsperpage = 0;
            $quiz->navmethod = 'free';
            $quiz->shuffleanswers = 1;
            $quiz->sumgrades = count($questionids);
            $quiz->grade = 10;
            $quiz->timecreated = time();
            $quiz->timemodified = time();
            $quiz->password = '';
            $quiz->subnet = '';
            $quiz->browsersecurity = '-';
            $quiz->delay1 = 0;
            $quiz->delay2 = 0;
            $quiz->showuserpicture = 0;
            $quiz->showblocks = 0;
            $quiz->completionattemptsexhausted = 0;
            $quiz->completionpass = 0;
            $quiz->allowofflineattempts = 0;
            $quizid = $DB->insert_record('quiz', $quiz);

            // Create course module FIRST so we have the context for question_references.
            $quizcm = new \stdClass();
            $quizcm->course = $course->id;
            $quizcm->module = $quizmodule->id;
            $quizcm->instance = $quizid;
            $quizcm->section = 0;
            $quizcm->visible = 1;
            $quizcm->visibleoncoursepage = 1;
            $quizcm->groupmode = 0;
            $quizcm->groupingid = 0;
            $quizcm->completion = 0;
            $quizcm->completiongradeitemnumber = null;
            $quizcm->completionview = 0;
            $quizcm->completionexpected = 0;
            $quizcm->showdescription = 0;
            $quizcm->availability = null;
            $quizcm->deletioninprogress = 0;
            $cmid = add_course_module($quizcm);

            course_add_cm_to_section($course, $cmid, 0);

            // Add questions to quiz_slots (+ question_references for Moodle 5.x).
            $quizcontext = \context_module::instance($cmid);
            foreach ($qbeids as $slot => $qbeid) {
                $quizslot = new \stdClass();
                $quizslot->quizid = $quizid;
                $quizslot->maxmark = 1;
                $quizslot->slot = $slot + 1;
                $quizslot->requireprevious = 0;
                $quizslot->page = $slot + 1;
                if ($slotshasqbeid) {
                    // Moodle 4.x: reference stored directly in slot.
                    $quizslot->questionbankentryid = $qbeid;
                    $DB->insert_record('quiz_slots', $quizslot);
                } else {
                    // Moodle 5.x: slot has no question reference; use question_references table.
                    $slotid = $DB->insert_record('quiz_slots', $quizslot);
                    if ($hasquestionrefs) {
                        $qref = new \stdClass();
                        $qref->usingcontextid = $quizcontext->id;
                        $qref->component = 'mod_quiz';
                        $qref->questionarea = 'slot';
                        $qref->itemid = $slotid;
                        $qref->questionbankentryid = $qbeid;
                        $qref->version = null;
                        $DB->insert_record('question_references', $qref);
                    }
                }
            }

            rebuild_course_cache($course->id, true);

            // Store the cmid in jitsi_source_record.
            $DB->set_field('jitsi_source_record', 'ai_quiz_id', $cmid, ['id' => $sourcerecord->id]);
            mtrace("generate_ai_quiz: created quiz (cmid={$cmid}) with " . count($questionids) . " questions");
        } catch (\Throwable $e) {
            mtrace("generate_ai_quiz: ERROR: " . $e->getMessage());
            $DB->set_field('jitsi_source_record', 'ai_quiz_id', -1, ['id' => $sourcerecord->id]);
        }
    }
}
