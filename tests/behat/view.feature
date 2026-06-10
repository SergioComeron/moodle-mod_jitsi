@mod @mod_jitsi
Feature: View a Jitsi activity
  In order to join and manage a Jitsi session
  As a teacher or student
  I need the activity page to show the right access state and tabs

  Background:
    Given the following "courses" exist:
      | fullname | shortname | category |
      | Course 1 | C1        | 0        |
    And the following "users" exist:
      | username | firstname | lastname | email                |
      | teacher1 | Teacher   | One      | teacher1@example.com |
      | student1 | Student   | One      | student1@example.com |
    And the following "course enrolments" exist:
      | user     | course | role           |
      | teacher1 | C1     | editingteacher |
      | student1 | C1     | student        |

  Scenario: An open session shows the Access button to a student
    Given the following "activities" exist:
      | activity | name       | intro      | course | idnumber |
      | jitsi    | Open Jitsi | Open intro | C1     | jitsi1   |
    When I am on the "Open Jitsi" "jitsi activity" page logged in as student1
    Then "Access" "link" should exist
    And I should not see "The session has not started"
    And I should not see "The session has finished"

  Scenario: A session that has not started yet hides the Access button
    Given the following "activities" exist:
      | activity | name         | intro     | course | idnumber | timeopen     |
      | jitsi    | Future Jitsi | Soon      | C1     | jitsi2   | ##tomorrow## |
    When I am on the "Future Jitsi" "jitsi activity" page logged in as student1
    Then "Access" "link" should not exist
    And I should see "The session has not started"

  Scenario: A finished session shows the finished notice
    Given the following "activities" exist:
      | activity | name       | intro | course | idnumber | timeclose     |
      | jitsi    | Past Jitsi | Over  | C1     | jitsi3   | ##yesterday## |
    When I am on the "Past Jitsi" "jitsi activity" page logged in as student1
    Then "Access" "link" should not exist
    And I should see "The session has finished"

  Scenario: A teacher sees the Recordings tab but a student without recordings does not
    Given the following "activities" exist:
      | activity | name       | intro  | course | idnumber |
      | jitsi    | Tab Jitsi  | Tabs   | C1     | jitsi4   |
    When I am on the "Tab Jitsi" "jitsi activity" page logged in as teacher1
    Then "Recordings" "link" should exist
    When I am on the "Tab Jitsi" "jitsi activity" page logged in as student1
    Then "Recordings" "link" should not exist
