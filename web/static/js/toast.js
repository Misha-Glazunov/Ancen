// Тост-уведомления в правом нижнем углу — общий механизм для всех страниц.
// Использование: window.showToast({ icon: '🏆', title: 'Достижение получено', body: 'Первая эмоция' })
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
        toast.innerHTML =
            (opts.icon ? '<span class="toast-icon">' + opts.icon + '</span>' : '') +
            '<span><div class="toast-title"></div><div class="toast-body"></div></span>';
        toast.querySelector('.toast-title').textContent = opts.title || '';
        toast.querySelector('.toast-body').textContent = opts.body || '';
        container.appendChild(toast);
        requestAnimationFrame(function () { toast.classList.add('in-view'); });
        setTimeout(function () {
            toast.classList.remove('in-view');
            setTimeout(function () { toast.remove(); }, 350);
        }, 5000);
    };
})();
