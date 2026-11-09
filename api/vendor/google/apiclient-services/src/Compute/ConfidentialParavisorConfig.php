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

class ConfidentialParavisorConfig extends \Google\Model
{
  /**
   * No TPM type specified. Do not use this value.
   */
  public const CONFIDENTIAL_TPM_TYPE_CONFIDENTIAL_TPM_TYPE_UNSPECIFIED = 'CONFIDENTIAL_TPM_TYPE_UNSPECIFIED';
  /**
   * An ephemeral vTPM running in the paravisor (SVSM).
   */
  public const CONFIDENTIAL_TPM_TYPE_EPHEMERAL = 'EPHEMERAL';
  /**
   * No confidential computing vTPM is used in the paravisor (SVSM).
   */
  public const CONFIDENTIAL_TPM_TYPE_NO_CC_TPM = 'NO_CC_TPM';
  /**
   * Restricted interrupt injection.
   */
  public const SEV_SNP_IRQ_MODE_RESTRICTED = 'RESTRICTED';
  /**
   * No IRQ mode specified. Do not use this value.
   */
  public const SEV_SNP_IRQ_MODE_SEV_SNP_IRQ_MODE_UNSPECIFIED = 'SEV_SNP_IRQ_MODE_UNSPECIFIED';
  /**
   * Unrestricted interrupt injection.
   */
  public const SEV_SNP_IRQ_MODE_UNRESTRICTED = 'UNRESTRICTED';
  /**
   * Defines the type of TPM to use for the confidential instance.
   *
   * @var string
   */
  public $confidentialTpmType;
  /**
   * Defines the IRQ mode to use for the confidential instance.
   *
   * @var string
   */
  public $sevSnpIrqMode;

  /**
   * Defines the type of TPM to use for the confidential instance.
   *
   * Accepted values: CONFIDENTIAL_TPM_TYPE_UNSPECIFIED, EPHEMERAL, NO_CC_TPM
   *
   * @param self::CONFIDENTIAL_TPM_TYPE_* $confidentialTpmType
   */
  public function setConfidentialTpmType($confidentialTpmType)
  {
    $this->confidentialTpmType = $confidentialTpmType;
  }
  /**
   * @return self::CONFIDENTIAL_TPM_TYPE_*
   */
  public function getConfidentialTpmType()
  {
    return $this->confidentialTpmType;
  }
  /**
   * Defines the IRQ mode to use for the confidential instance.
   *
   * Accepted values: RESTRICTED, SEV_SNP_IRQ_MODE_UNSPECIFIED, UNRESTRICTED
   *
   * @param self::SEV_SNP_IRQ_MODE_* $sevSnpIrqMode
   */
  public function setSevSnpIrqMode($sevSnpIrqMode)
  {
    $this->sevSnpIrqMode = $sevSnpIrqMode;
  }
  /**
   * @return self::SEV_SNP_IRQ_MODE_*
   */
  public function getSevSnpIrqMode()
  {
    return $this->sevSnpIrqMode;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(ConfidentialParavisorConfig::class, 'Google_Service_Compute_ConfidentialParavisorConfig');
