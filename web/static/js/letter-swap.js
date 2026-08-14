// Letter Swap hover — портирован с "Random Letter Swap" (Originkit, framer-motion)
// на ванильный JS/CSS: для пунктов меню header/footer буквы по одной, в случайном
// порядке, уезжают вверх на hover-enter и возвращаются на hover-leave (pingpong).
(function () {
    var STAGGER_MS = 35; // задержка между буквами (аналог staggerDuration)

    function shuffle(arr) {
        var a = arr.slice();
        a.sort(function () { return Math.random() - 0.5; });
        return a;
    }

    function buildLetters(text) {
        var frag = document.createDocumentFragment();
        var slots = [];
        for (var i = 0; i < text.length; i++) {
            var ch = text[i];
            var slot = document.createElement('span');
            slot.className = 'letter-slot';
            if (ch === ' ') {
                slot.innerHTML = '&nbsp;';
                frag.appendChild(slot);
                continue;
            }
            var primary = document.createElement('span');
            primary.className = 'letter letter-primary';
            primary.textContent = ch;
            var secondary = document.createElement('span');
            secondary.className = 'letter letter-secondary';
            secondary.textContent = ch;
            slot.appendChild(primary);
            slot.appendChild(secondary);
            frag.appendChild(slot);
            slots.push(slot);
        }
        return { frag: frag, slots: slots };
    }

    // Как buildLetters, но всё слово — один slot: уезжает вверх целиком,
    // а не по буквам (для header, где нужна более сдержанная анимация).
    function buildWord(text) {
        var frag = document.createDocumentFragment();
        var slot = document.createElement('span');
        slot.className = 'letter-slot letter-slot-word';
        var primary = document.createElement('span');
        primary.className = 'letter letter-primary';
        primary.textContent = text;
        var secondary = document.createElement('span');
        secondary.className = 'letter letter-secondary';
        secondary.textContent = text;
        slot.appendChild(primary);
        slot.appendChild(secondary);
        frag.appendChild(slot);
        return { frag: frag, slots: [slot] };
    }

    function initLetterSwap(el) {
        if (el.dataset.letterSwapInit) return;
        var text = el.textContent.trim();
        if (!text) return;
        el.dataset.letterSwapInit = '1';
        el.textContent = '';
        var wrap = document.createElement('span');
        wrap.className = 'letter-swap';
        var built = el.hasAttribute('data-swap-word') ? buildWord(text) : buildLetters(text);
        wrap.appendChild(built.frag);
        el.appendChild(wrap);

        var slots = built.slots;

        function play(toActive) {
            shuffle(slots).forEach(function (slot, i) {
                var delay = i * STAGGER_MS + 'ms';
                // transition-delay не наследуется — ставим на сами буквы
                // (у slot анимируемых свойств нет), иначе все буквы слова
                // переключаются разом, без раскадровки по буквам.
                slot.querySelectorAll('.letter').forEach(function (letter) {
                    letter.style.transitionDelay = delay;
                });
                slot.classList.toggle('is-active', toActive);
            });
        }

        el.addEventListener('mouseenter', function () { play(true); });
        el.addEventListener('mouseleave', function () { play(false); });
    }

    var SELECTOR = '.header-nav a, .header-logout, .button-login-registry, .footer-col a, .policy-button';

    function init() {
        document.querySelectorAll(SELECTOR).forEach(initLetterSwap);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
