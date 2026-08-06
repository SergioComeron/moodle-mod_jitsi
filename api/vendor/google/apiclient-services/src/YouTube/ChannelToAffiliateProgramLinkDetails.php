<?php
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

namespace Google\Service\YouTube;

class ChannelToAffiliateProgramLinkDetails extends \Google\Model
{
  /**
   * Unspecified status.
   */
  public const PROGRAM_STATUS_affiliateProgramStatusUnspecified = 'affiliateProgramStatusUnspecified';
  /**
   * Channel is active in the affiliate program.
   */
  public const PROGRAM_STATUS_active = 'active';
  /**
   * Channel is inactive in the affiliate program.
   */
  public const PROGRAM_STATUS_inactive = 'inactive';
  /**
   * Required. Google Merchant Center ID of the partner.
   *
   * @var string
   */
  public $merchantId;
  /**
   * Required. Affiliate program status.
   *
   * @var string
   */
  public $programStatus;
  /**
   * Optional. Reason for the last update of the affiliate program status.
   *
   * @var string
   */
  public $statusUpdateReason;
  /**
   * Optional. Timestamp when the affiliate program status was last updated.
   *
   * @var string
   */
  public $statusUpdateTime;

  /**
   * Required. Google Merchant Center ID of the partner.
   *
   * @param string $merchantId
   */
  public function setMerchantId($merchantId)
  {
    $this->merchantId = $merchantId;
  }
  /**
   * @return string
   */
  public function getMerchantId()
  {
    return $this->merchantId;
  }
  /**
   * Required. Affiliate program status.
   *
   * Accepted values: affiliateProgramStatusUnspecified, active, inactive
   *
   * @param self::PROGRAM_STATUS_* $programStatus
   */
  public function setProgramStatus($programStatus)
  {
    $this->programStatus = $programStatus;
  }
  /**
   * @return self::PROGRAM_STATUS_*
   */
  public function getProgramStatus()
  {
    return $this->programStatus;
  }
  /**
   * Optional. Reason for the last update of the affiliate program status.
   *
   * @param string $statusUpdateReason
   */
  public function setStatusUpdateReason($statusUpdateReason)
  {
    $this->statusUpdateReason = $statusUpdateReason;
  }
  /**
   * @return string
   */
  public function getStatusUpdateReason()
  {
    return $this->statusUpdateReason;
  }
  /**
   * Optional. Timestamp when the affiliate program status was last updated.
   *
   * @param string $statusUpdateTime
   */
  public function setStatusUpdateTime($statusUpdateTime)
  {
    $this->statusUpdateTime = $statusUpdateTime;
  }
  /**
   * @return string
   */
  public function getStatusUpdateTime()
  {
    return $this->statusUpdateTime;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(ChannelToAffiliateProgramLinkDetails::class, 'Google_Service_YouTube_ChannelToAffiliateProgramLinkDetails');
