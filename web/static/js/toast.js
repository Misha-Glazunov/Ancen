// Тост-уведомления в правом нижнем углу — общий механизм для всех страниц.
// Использование: window.showToast({ icon: '🏆', title: 'Достижение получено', body: 'Первая эмоция' })
// С кнопками действия (не гаснет по клику мимо, только по кнопке/таймауту):
//   window.showToast({ icon: '🎬', title: '...', body: '...',
//     actions: [{ label: 'Принять', onClick: fn }, { label: 'Отклонить', onClick: fn }] })
// Кликабельный целиком (например, переход к диалогу по клику на тост о сообщении):
//   window.showToast({ icon: '💬', title: '...', body: '...', onClick: fn })
(function () {
    function ensureContainer() {
        var el = document.getElementById('toast-container');
        if (!el) {
            el = document.createElement('div');
            el.id = 'toast-container';
            document.body.appendChild(el);
        }
        return el;
    }

    window.showToast = function (opts) {
        var container = ensureContainer();
        var toast = document.createElement('div');
        toast.className = 'toast';
        var actions = opts.actions || [];
        var actionsHtml = actions.length
            ? '<div class="toast-actions">' + actions.map(function (a, i) {
                return '<button type="button" class="btn btn-sm toast-action-btn" data-action-index="' + i + '">' + a.label + '</button>';
            }).join('') + '</div>'
            : '';
        toast.innerHTML =
            (opts.icon ? '<span class="toast-icon">' + opts.icon + '</span>' : '') +
            '<span class="toast-content"><div class="toast-title"></div><div class="toast-body"></div>' + actionsHtml + '</span>';
        toast.querySelector('.toast-title').textContent = opts.title || '';
        toast.querySelector('.toast-body').textContent = opts.body || '';

        var dismissed = false;
        function dismiss() {
            if (dismissed) return;
            dismissed = true;
            toast.classList.remove('in-view');
            setTimeout(function () { toast.remove(); }, 350);
        }
        toast.querySelectorAll('.toast-action-btn').forEach(function (btn, i) {
            btn.addEventListener('click', function (e) {
                e.stopPropagation(); // не даём всплыть до обработчика клика по всему тосту
                actions[i].onClick();
                dismiss();
            });
        });
        if (opts.onClick) {
            toast.classList.add('is-clickable');
            toast.addEventListener('click', function () {
                opts.onClick();
                dismiss();
            });
        }

        container.appendChild(toast);
        requestAnimationFrame(function () { toast.classList.add('in-view'); });
        setTimeout(dismiss, opts.duration || 5000);
    };
})();
