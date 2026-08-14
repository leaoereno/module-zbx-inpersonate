<?php declare(strict_types=1);
/**
 * Impersonate - log de auditoria das impersonacoes.
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Actions;

use CController;
use CControllerResponseData;
use Modules\ZbxImpersonate\Helper\ImpersonateHelper;

class ImpersonateLog extends CController {

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		return $this->validateInput([
			'search' => 'string',
			'limit'  => 'in 50,100,200,500,1000'
		]);
	}

	protected function checkPermissions(): bool {
		return $this->getUserType() == USER_TYPE_SUPER_ADMIN;
	}

	protected function doAction(): void {
		$search = trim((string) $this->getInput('search', ''));
		$limit = (int) $this->getInput('limit', 200);

		$rows = ImpersonateHelper::getLog($limit, $search);

		$open = 0;
		$total_seconds = 0;
		$closed = 0;

		foreach ($rows as $row) {
			if ((int) $row['ended'] === 0) {
				$open++;
			}
			else {
				$closed++;
				$total_seconds += max(0, (int) $row['ended'] - (int) $row['started']);
			}
		}

		$this->setResponse(new CControllerResponseData([
			'rows'   => $rows,
			'search' => $search,
			'limit'  => $limit,
			'stats'  => [
				'total'    => count($rows),
				'open'     => $open,
				'avg'      => $closed > 0 ? ImpersonateHelper::formatDuration((int) round($total_seconds / $closed)) : '-'
			]
		]));
	}
}
