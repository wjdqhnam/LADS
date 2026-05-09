function toggleMenu(force) {
  var menu = document.getElementById('mobile-menu');
  if (!menu) return;
  if (force === false) menu.classList.add('hidden');
  else menu.classList.toggle('hidden');
}

var _es = null;
var _currentTask = null;
var _labels = {
  crawl: '크롤링',
  payload: '페이로드 준비',
  scan: '스캔 실행',
  fuzz: '스캔 작업 생성',
  execute: '활성 스캔',
  validate: '결과 분석',
  all: '전체 진단'
};

function runTask(task) {
  _startStream('/stream/' + task);
}

function runTaskAll() {
  _startStream('/stream/all');
}

function _setButtons(disabled) {
  document.querySelectorAll('button').forEach(function (button) {
    button.disabled = disabled;
  });
}

function _setPipelineLoading(taskName) {
  var steps = Array.prototype.slice.call(document.querySelectorAll('.pipeline-step-card'));
  var targetIndex = taskName === 'all' ? 0 : steps.findIndex(function (step) {
    return step.dataset.task === taskName;
  });

  if (targetIndex >= 0) {
    var percent = taskName === 'all' ? 0 : Math.round((targetIndex / Math.max(steps.length, 1)) * 100);
    _updateProgressBar(percent);
  }

  steps.forEach(function (step) {
    var node = step.querySelector('.pipeline-node');
    var status = step.querySelector('.pipeline-status');
    if (!node || !status) return;

    if (taskName === 'all') {
      if (step.dataset.task === 'crawl') {
        node.className = 'pipeline-node animate-pulse';
        status.textContent = 'Loading';
        status.className = 'pipeline-status text-amber-600';
        step.classList.remove('pending');
        step.classList.add('active');
      }
      return;
    }

    if (step.dataset.task === taskName) {
      node.className = 'pipeline-node animate-pulse';
      status.textContent = 'Loading';
      status.className = 'pipeline-status text-amber-600';
      step.classList.remove('pending');
      step.classList.add('active');
    }
  });
}

function _badgeClass(kind) {
  if (kind === 'ok') {
    return 'inline-flex items-center gap-2 rounded bg-emerald-50 px-2 py-1 font-mono text-[12px] uppercase text-emerald-700';
  }
  if (kind === 'error') {
    return 'inline-flex items-center gap-2 rounded bg-red-50 px-2 py-1 font-mono text-[12px] uppercase text-red-700';
  }
  return 'inline-flex items-center gap-2 rounded bg-amber-50 px-2 py-1 font-mono text-[12px] uppercase text-amber-700';
}

function _stageFromMessage(message) {
  var text = message.toLowerCase();
  if (text.indexOf('crawl') !== -1 || text.indexOf('크롤') !== -1 || text.indexOf('crawler') !== -1) {
    return { label: 'CRAWL', cls: 'bg-sky-100 text-sky-800', row: 'bg-sky-50' };
  }
  if (text.indexOf('payload') !== -1 || text.indexOf('페이로드') !== -1 || text.indexOf('llm') !== -1) {
    return { label: 'PAYLOAD', cls: 'bg-violet-100 text-violet-800', row: 'bg-violet-50' };
  }
  if (text.indexOf('fuzz') !== -1 || text.indexOf('퍼징') !== -1 || text.indexOf('strategy') !== -1) {
    return { label: 'FUZZ', cls: 'bg-amber-100 text-amber-800', row: 'bg-amber-50' };
  }
  if (text.indexOf('execute') !== -1 || text.indexOf('실행') !== -1 || text.indexOf('request') !== -1) {
    return { label: 'EXEC', cls: 'bg-indigo-100 text-indigo-800', row: 'bg-indigo-50' };
  }
  if (text.indexOf('validate') !== -1 || text.indexOf('분석') !== -1 || text.indexOf('판정') !== -1 || text.indexOf('취약') !== -1) {
    return { label: 'VALIDATE', cls: 'bg-rose-100 text-rose-800', row: 'bg-rose-50' };
  }
  if (text.indexOf('__progress__') !== -1 || text.indexOf('progress') !== -1) {
    return { label: 'PROGRESS', cls: 'bg-emerald-100 text-emerald-800', row: 'bg-emerald-50' };
  }
  return { label: 'SYSTEM', cls: 'bg-slate-100 text-slate-700', row: '' };
}

function _updateProgressBar(percent) {
  percent = Math.max(0, Math.min(100, percent));
  var percentLabel = document.getElementById('pipeline-percent');
  var bar = document.getElementById('pipeline-progress-bar');
  if (percentLabel) percentLabel.textContent = percent + '%';
  if (bar) {
    bar.style.width = percent + '%';
    if (percent >= 100) {
      bar.className = 'h-full rounded-full bg-emerald-500 transition-all duration-500';
    } else {
      bar.className = 'h-full rounded-full bg-amber-500 transition-all duration-300';
    }
  }
}

function _startStream(url) {
  if (_es) {
    _es.close();
    _es = null;
  }

  var logCard = document.getElementById('log-card');
  var logArea = document.getElementById('log-area');
  var logTitle = document.getElementById('log-title');
  var logBadge = document.getElementById('log-badge');
  if (!logCard || !logArea || !logTitle || !logBadge) return;

  var taskName = url.split('/stream/')[1].split('?')[0];
  _currentTask = taskName;
  _setPipelineLoading(taskName);

  logTitle.textContent = (_labels[taskName] || taskName) + ' 로그';
  logBadge.textContent = 'Running';
  logBadge.className = _badgeClass('running');
  logArea.textContent = '';
  _setButtons(true);

  _es = new EventSource(url);
  _es.onmessage = function (event) {
    if (event.data === '__DONE__') {
      _es.close();
      _es = null;
      logBadge.textContent = 'Done';
      logBadge.className = _badgeClass('ok');
      _updateProgressBar(100);
      _setButtons(false);
      var isFullScan = _currentTask === 'all';
      setTimeout(function () {
        if (isFullScan) {
          window.location.href = '/findings';
        } else {
          location.reload();
        }
      }, 1500);
      return;
    }

    if (event.data.startsWith('__PROGRESS__')) {
      var pct = parseInt(event.data.replace('__PROGRESS__', ''), 10);
      _updateProgressBar(pct);
      return;
    }

    var stage = _stageFromMessage(event.data);
    var row = document.createElement('div');
    row.className = 'flex gap-4 rounded px-2 py-1 ' + stage.row;

    var time = document.createElement('span');
    time.className = 'w-[70px] shrink-0 text-outline';
    time.textContent = new Date().toLocaleTimeString('ko-KR', { hour12: false });

    var stageBadge = document.createElement('span');
    stageBadge.className = 'w-[82px] shrink-0 rounded px-2 text-center text-[11px] font-black ' + stage.cls;
    stageBadge.textContent = stage.label;

    var level = document.createElement('span');
    level.className = 'w-[52px] shrink-0 text-secondary';
    level.textContent = event.data.indexOf('[ERROR]') !== -1 ? '[ERROR]' : event.data.indexOf('[WARN]') !== -1 ? '[WARN]' : '[INFO]';

    var message = document.createElement('span');
    message.className = event.data.indexOf('[ERROR]') !== -1 ? 'text-error' : 'text-slate-950';
    message.textContent = event.data;

    row.appendChild(time);
    row.appendChild(stageBadge);
    row.appendChild(level);
    row.appendChild(message);
    logArea.appendChild(row);
    logArea.scrollTop = logArea.scrollHeight;
  };

  _es.onerror = function () {
    if (_es) {
      _es.close();
      _es = null;
    }
    logBadge.textContent = 'Error';
    logBadge.className = _badgeClass('error');
    _setButtons(false);
    var row = document.createElement('div');
    row.className = 'text-error';
    row.textContent = '[연결 오류] 서버 상태를 확인하세요.';
    logArea.appendChild(row);
  };
}
