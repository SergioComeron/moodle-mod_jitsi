@mod @mod_jitsi
Feature: Validate open and close dates when editing a jitsi activity
  In order to keep session availability windows consistent
  As a teacher
  I need the activity form to reject a close date that is before the open date

  Background:
    Given the following "courses" exist:
      | fullname | shortname | category |
      | Course 1 | C1        | 0        |
    And the following "users" exist:
      | username | firstname | lastname | email                |
      | teacher1 | Teacher   | One      | teacher1@example.com |
    And the following "course enrolments" exist:
      | user     | course | role           |
      | teacher1 | C1     | editingteacher |

  Scenario: Saving with a close date before the open date is rejected
    Given I am on the "Course 1" course page logged in as teacher1
    When I add a "jitsi" activity to course "Course 1" section "1"
    And I set the following fields to these values:
      | Session name       | Dated Jitsi |
      | timeopen[enabled]  | 1           |
      | timeopen[day]      | 31          |
      | timeopen[month]    | December    |
      | timeclose[enabled] | 1           |
      | timeclose[day]     | 1           |
      | timeclose[month]   | January     |
    And I press "Save and return to course"
    Then I should see "close date before the open date"

  Scenario: Saving with a close date after the open date succeeds
    Given I am on the "Course 1" course page logged in as teacher1
    When I add a "jitsi" activity to course "Course 1" section "1"
    And I set the following fields to these values:
      | Session name       | Valid Jitsi |
      | timeopen[enabled]  | 1           |
      | timeopen[day]      | 1           |
      | timeopen[month]    | January     |
      | timeclose[enabled] | 1           |
      | timeclose[day]     | 31          |
      | timeclose[month]   | December    |
    And I press "Save and return to course"
    Then I should not see "close date before the open date"
    And I should see "Valid Jitsi"
