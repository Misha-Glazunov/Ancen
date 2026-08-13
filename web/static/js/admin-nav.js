// Header pill-nav на всех страницах /admin — плавный "переливающийся"
// индикатор следует за наведённым пунктом внутри своей группы (.nav-group)
// и возвращается к активному пункту той же группы.
(function () {
  document.querySelectorAll('.nav-group').forEach(function (group) {
    const liquid = group.querySelector('.nav-liquid');
    const pills = Array.from(group.querySelectorAll('.nav-pill[data-pill]'));
    if (!liquid || !pills.length) return;
    const active = group.querySelector('.nav-pill.active') || null;

    function moveTo(el) {
      if (!el) { liquid.style.opacity = 0; return; }
      liquid.style.opacity = 1;
      liquid.style.left = el.offsetLeft + 'px';
      liquid.style.top = el.offsetTop + 'px';
      liquid.style.width = el.offsetWidth + 'px';
      liquid.style.height = el.offsetHeight + 'px';
    }
    moveTo(active);
    pills.forEach(p => {
      p.addEventListener('mouseenter', () => { p.classList.add('liquid-hover'); moveTo(p); });
      p.addEventListener('mouseleave', () => { p.classList.remove('liquid-hover'); moveTo(active); });
    });
    window.addEventListener('resize', () => moveTo(group.querySelector('.liquid-hover') || active));
  });
})();
