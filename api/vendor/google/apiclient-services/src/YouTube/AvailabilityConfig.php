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

class AvailabilityConfig extends \Google\Model
{
  protected $globalConfigType = AvailabilityConfigGlobalConfig::class;
  protected $globalConfigDataType = '';
  protected $regionsConfigType = AvailabilityConfigRegionsConfig::class;
  protected $regionsConfigDataType = '';

  /**
   * Video is available in all regions except the ones specified in the config.
   *
   * @param AvailabilityConfigGlobalConfig $globalConfig
   */
  public function setGlobalConfig(AvailabilityConfigGlobalConfig $globalConfig)
  {
    $this->globalConfig = $globalConfig;
  }
  /**
   * @return AvailabilityConfigGlobalConfig
   */
  public function getGlobalConfig()
  {
    return $this->globalConfig;
  }
  /**
   * Video is available in the specified regions only.
   *
   * @param AvailabilityConfigRegionsConfig $regionsConfig
   */
  public function setRegionsConfig(AvailabilityConfigRegionsConfig $regionsConfig)
  {
    $this->regionsConfig = $regionsConfig;
  }
  /**
   * @return AvailabilityConfigRegionsConfig
   */
  public function getRegionsConfig()
  {
    return $this->regionsConfig;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(AvailabilityConfig::class, 'Google_Service_YouTube_AvailabilityConfig');
