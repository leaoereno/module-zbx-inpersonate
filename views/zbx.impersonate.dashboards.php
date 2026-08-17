<?php declare(strict_types=1);
/**
 * Impersonate - resposta JSON da lista de dashboards (layout.json).
 *
 * @var CView $this
 * @var array $data
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

echo json_encode($data['payload'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
