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

class BrandPartner extends \Google\Model
{
  /**
   * Required. Channel handle, must begin with "@"
   *
   * @var string
   */
  public $channelHandle;
  /**
   * Required. External Channel ID, must begin with "UC"
   *
   * @var string
   */
  public $channelId;

  /**
   * Required. Channel handle, must begin with "@"
   *
   * @param string $channelHandle
   */
  public function setChannelHandle($channelHandle)
  {
    $this->channelHandle = $channelHandle;
  }
  /**
   * @return string
   */
  public function getChannelHandle()
  {
    return $this->channelHandle;
  }
  /**
   * Required. External Channel ID, must begin with "UC"
   *
   * @param string $channelId
   */
  public function setChannelId($channelId)
  {
    $this->channelId = $channelId;
  }
  /**
   * @return string
   */
  public function getChannelId()
  {
    return $this->channelId;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(BrandPartner::class, 'Google_Service_YouTube_BrandPartner');
