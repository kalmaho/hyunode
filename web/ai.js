'use strict';
let aiPreview = null;

function aiPanel() {
  const cfg = state.config.ai || {};
  const local = cfg.source === 'local_ollama';
  const scans = state.scans.filter(s => s.result && ['completed', 'partial'].includes(s.status));
  const runs = state.ai_runs || [];
  const running = runs.some(r => ['queued', 'running'].includes(r.status));
  return `<section class="panel"><div class="panel-head"><div><h2>AI 심층 분석</h2><p class="panel-sub">관찰된 사실과 가설을 구분하는 근거 기반 리뷰</p></div>${badge('관리자 전용', 'blue')}</div>
    <div class="ai-intro"><div class="ai-symbol">✧</div><div><h3>근거를 연결하고, 다음 검사를 설계하세요.</h3><p>포트와 HTTP 구조를 함께 검토해 전제조건·오탐 가능성·개선 우선순위를 제안합니다. 실제 취약점 재현과 추가 요청은 자동 실행하지 않습니다.</p></div></div>
    <div class="ai-config"><span>${local ? '로컬 Ollama' : 'OpenAI'} · ${cfg.configured ? esc(cfg.model) : '서버 설정 필요'}</span><span>로컬 접속 전용 · 하루 최대 20회 · 자동 재시도 없음</span></div>
    ${local ? '<div class="inline-hint">소형 로컬 모델은 HTTP 설정 요약·개선 우선순위만 작성합니다. 관찰 사실과 근거 ID는 검사 엔진에서 가져오며, 취약점 가설 생성은 지원하지 않습니다. 권고 내용은 수동 검토가 필요합니다.</div>' : ''}
    ${!cfg.configured && local ? '<div class="inline-hint">Ollama와 로컬 모델을 실행하세요. 외부 API로 자동 전환하지 않습니다.</div>' : ''}
    ${!cfg.configured && !local ? '<div class="inline-hint">Windows는 <code>python configure_ai.py</code>로 API 키와 모델을 한 번 저장하면 됩니다. 다른 환경은 <code>OPENAI_API_KEY</code>와 <code>OPENAI_MODEL</code>을 설정하세요. API 키를 이 화면이나 GitHub에 입력하지 않습니다.</div>' : ''}
    ${scans.length ? scans.map(s => `<div class="report-row"><div><strong>${esc(s.name)} · 검사 #${s.id}</strong><p>${stamp(s.created)} · 근거 ${s.result.observations ? '구조 정보 포함' : '기존 기본 정보'} · 관찰 ${s.result.findings.length}건</p></div><button class="secondary" data-ai-preview="${s.id}" ${running ? 'disabled' : ''}>전송 근거 확인</button></div>`).join('') : empty('분석할 검사 결과가 없습니다', '실습 대상을 검사한 후 AI 분석을 시작하세요.')}
    </section><section class="panel"><div class="panel-head"><h2>AI 분석 기록</h2><span class="panel-sub">실측 결과와 별도로 보관</span></div>${runs.length ? runs.map(r => {
      const a = r.result?.analysis;
      return `<article class="ai-run"><div class="ai-run-head"><strong>검사 #${r.scan_id} · 분석 #${r.id}</strong>${badge(labels[r.status] || r.status, r.status === 'completed' ? 'green' : 'orange')}</div><p class="panel-sub">${stamp(r.created)}${r.result?.model ? ' · ' + esc(r.result.model) : ''}</p>
        ${a ? `<p class="ai-summary">${esc(a.summary)}</p><h3>관찰된 사실</h3>${a.observed_facts.map(f => `<div class="ai-fact">${esc(f.statement)}<small>${f.evidence_ids.map(esc).join(' · ')}</small></div>`).join('')}
        <h3>취약점 가설 · 수동 검토 필요</h3>${a.hypotheses.map(h => `<div class="ai-hypothesis"><div class="ai-run-head"><strong>${esc(h.title)}</strong>${badge('확신도 ' + ({low:'낮음',medium:'중간',high:'높음'}[h.confidence]), 'blue')}</div><small class="panel-sub">참조 근거 ${h.evidence_ids.map(esc).join(' · ')}</small><dl>${[['전제조건',h.prerequisites],['예상 영향',h.possible_impact],['오탐 가능성',h.false_positive_risk],['추가 확인 절차 · 미실행',h.manual_verification],['권장 개선',h.remediation]].map(([title,text]) => `<dt>${title}</dt><dd>${esc(text)}</dd>`).join('')}</dl></div>`).join('')}
        <div class="ai-columns"><div><h3>개선 우선순위</h3><ul>${a.priorities.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div><div><h3>검사 범위의 한계</h3><ul>${a.coverage_gaps.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div></div>
        <div class="ai-actions"><span class="panel-sub">사용량 ${r.result.usage.total_tokens} tokens · AI 제안은 검증 결과가 아닙니다.</span><button class="secondary" data-ai-report="${r.id}">AI 보고서 다운로드</button></div>` : r.result?.error ? `<p class="error">${esc(r.result.error)}</p>` : `<p class="inline-hint">${['queued','running'].includes(r.status) ? '근거를 분석하고 있습니다. 완료 시 자동으로 갱신됩니다.' : '서버 재시작으로 중단된 분석입니다. 필요하면 다시 실행하세요.'}</p>`}</article>`;
    }).join('') : empty('아직 AI 분석 기록이 없습니다', '자동 검사 후 근거를 확인하고 분석을 실행하세요.')}</section>`;
}

function aiReport(id) {
  const run = state.ai_runs.find(r => r.id === Number(id));
  const a = run.result.analysis;
  const text = `# Hyunode AI 분석 · 검사 #${run.scan_id}\n\n모델: ${run.result.model}\n분석 시각: ${run.created}\nAI 제안은 재현 검증 결과가 아닙니다.\n\n## 요약\n${a.summary}\n\n## 관찰된 사실\n${a.observed_facts.map(f=>`- ${f.statement} [${f.evidence_ids.join(', ')}]`).join('\n')}\n\n## 가설\n${a.hypotheses.map(h=>`### ${h.title}\n근거: ${h.evidence_ids.join(', ')} / 확신도: ${h.confidence}\n\n전제조건: ${h.prerequisites}\n\n예상 영향: ${h.possible_impact}\n\n오탐 가능성: ${h.false_positive_risk}\n\n추가 확인 절차 (미실행): ${h.manual_verification}\n\n개선: ${h.remediation}\n`).join('\n')}\n## 우선순위\n${a.priorities.map(x=>'- '+x).join('\n')}\n\n## 한계\n${a.coverage_gaps.map(x=>'- '+x).join('\n')}\n\n## 전송된 구조 근거\n\n\`\`\`json\n${JSON.stringify(run.result.evidence,null,2)}\n\`\`\`\n`;
  const url = URL.createObjectURL(new Blob([text], {type:'text/markdown;charset=utf-8'}));
  const link = document.createElement('a');
  link.href=url; link.download=`hyunode-ai-${run.id}.md`; link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}

document.addEventListener('DOMContentLoaded', () => {
  names.ai = ['AI 심층 분석', '근거에서, 더 깊은 통찰로.', '관찰된 사실과 가설을 나누고 다음 검사의 우선순위를 정하세요.'];
  const nav = document.createElement('button');
  nav.className = 'nav'; nav.dataset.page = 'ai';
  nav.innerHTML = '<span>✧</span>AI 심층 분석';
  document.querySelector('nav').appendChild(nav);
  $('#ai-consent').addEventListener('change', () => {
    $('#send-ai').disabled = !$('#ai-consent').checked || !aiPreview?.settings.configured;
  });
});

document.addEventListener('click', async e => {
  const b = e.target.closest('button');
  if (!b) return;
  if (b.id === 'close-ai') $('#ai-dialog').close();
  if (b.dataset.aiReport) aiReport(b.dataset.aiReport);
  if (b.dataset.aiPreview) {
    b.disabled = true;
    try {
      aiPreview = await api('/api/ai/preview', {scan_id: Number(b.dataset.aiPreview)});
      aiPreview.scan_id = Number(b.dataset.aiPreview);
      $('#ai-preview').textContent = JSON.stringify(aiPreview.bundle, null, 2);
      $('#ai-consent').checked = false;
      $('#send-ai').disabled = true;
      const local = aiPreview.settings.source === 'local_ollama';
      $('#ai-transfer-note').textContent = local ? '아래 구조 정보를 이 PC의 Ollama로 전달합니다. 외부 AI API로 전송하지 않으며 API 요금은 없습니다. CPU·메모리를 사용하고 분석에 수 분이 걸릴 수 있습니다.' : '아래 구조 정보를 OpenAI API로 전송합니다. API 사용 요금이 발생할 수 있습니다. 대상 주소·이름, 쿠키 값, HTML 원문은 포함하지 않습니다.';
      $('#ai-consent-label').textContent = local ? '위 근거를 이 PC의 로컬 AI로 분석하는 데 동의합니다.' : '위 근거를 OpenAI로 전송하는 데 동의합니다.';
      $('#send-ai').textContent = local ? '로컬 AI 분석 실행' : 'OpenAI 분석 실행';
      $('#ai-error').textContent = aiPreview.settings.configured ? '' : (local ? 'Ollama 또는 설정한 로컬 모델을 찾을 수 없습니다.' : 'API 설정이 없습니다. Windows 터미널에서 python configure_ai.py를 실행하세요.');
      $('#ai-dialog').showModal();
    } catch (error) { toast(error.message); }
    finally { b.disabled = false; }
  }
  if (b.id === 'send-ai') {
    b.disabled = true;
    try {
      await api('/api/ai/analyze', {scan_id: aiPreview.scan_id, digest: aiPreview.digest, consent: $('#ai-consent').checked});
      $('#ai-dialog').close();
      page = 'ai';
      await refresh();
      toast('AI 분석을 시작했어요. 추가 검사 요청은 실행하지 않습니다.');
    } catch (error) { $('#ai-error').textContent = error.message; b.disabled = false; }
  }
});
