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

namespace Google\Service\Compute;

class ConfidentialInstanceConfig extends \Google\Model
{
  /**
   * Bare Metal Secure AI.
   */
  public const CONFIDENTIAL_INSTANCE_TYPE_BMSAI = 'BMSAI';
  /**
   * Arm Confidential Compute Architecture.
   */
  public const CONFIDENTIAL_INSTANCE_TYPE_CCA = 'CCA';
  /**
   * No type specified. Do not use this value.
   */
  public const CONFIDENTIAL_INSTANCE_TYPE_CONFIDENTIAL_INSTANCE_TYPE_UNSPECIFIED = 'CONFIDENTIAL_INSTANCE_TYPE_UNSPECIFIED';
  /**
   * AMD Secure Encrypted Virtualization.
   */
  public const CONFIDENTIAL_INSTANCE_TYPE_SEV = 'SEV';
  /**
   * AMD Secure Encrypted Virtualization - Secure Nested Paging.
   */
  public const CONFIDENTIAL_INSTANCE_TYPE_SEV_SNP = 'SEV_SNP';
  /**
   * Intel Trust Domain eXtension.
   */
  public const CONFIDENTIAL_INSTANCE_TYPE_TDX = 'TDX';
  /**
   * Defines the type of technology used by the confidential instance.
   *
   * @var string
   */
  public $confidentialInstanceType;
  protected $confidentialParavisorConfigType = ConfidentialParavisorConfig::class;
  protected $confidentialParavisorConfigDataType = '';
  /**
   * Defines whether the instance should have confidential compute enabled. When
   * enabled, the technology used defaults to  AMD SEV unless
   * confidentialInstanceType is specified.
   *
   * @var bool
   */
  public $enableConfidentialCompute;

  /**
   * Defines the type of technology used by the confidential instance.
   *
   * Accepted values: BMSAI, CCA, CONFIDENTIAL_INSTANCE_TYPE_UNSPECIFIED, SEV,
   * SEV_SNP, TDX
   *
   * @param self::CONFIDENTIAL_INSTANCE_TYPE_* $confidentialInstanceType
   */
  public function setConfidentialInstanceType($confidentialInstanceType)
  {
    $this->confidentialInstanceType = $confidentialInstanceType;
  }
  /**
   * @return self::CONFIDENTIAL_INSTANCE_TYPE_*
   */
  public function getConfidentialInstanceType()
  {
    return $this->confidentialInstanceType;
  }
  /**
   * Defines a set of Confidential Paravisor (SVSM) options.
   *
   * @param ConfidentialParavisorConfig $confidentialParavisorConfig
   */
  public function setConfidentialParavisorConfig(ConfidentialParavisorConfig $confidentialParavisorConfig)
  {
    $this->confidentialParavisorConfig = $confidentialParavisorConfig;
  }
  /**
   * @return ConfidentialParavisorConfig
   */
  public function getConfidentialParavisorConfig()
  {
    return $this->confidentialParavisorConfig;
  }
  /**
   * Defines whether the instance should have confidential compute enabled. When
   * enabled, the technology used defaults to  AMD SEV unless
   * confidentialInstanceType is specified.
   *
   * @param bool $enableConfidentialCompute
   */
  public function setEnableConfidentialCompute($enableConfidentialCompute)
  {
    $this->enableConfidentialCompute = $enableConfidentialCompute;
  }
  /**
   * @return bool
   */
  public function getEnableConfidentialCompute()
  {
    return $this->enableConfidentialCompute;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(ConfidentialInstanceConfig::class, 'Google_Service_Compute_ConfidentialInstanceConfig');
