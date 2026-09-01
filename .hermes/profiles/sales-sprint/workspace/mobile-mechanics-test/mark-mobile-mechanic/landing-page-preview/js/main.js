/**
 * Mark Mobile Mechanic.LLC — Landing Page
 * Mobile call bar reveal on hero scroll-past.
 * Progressive enhancement: page works without JS (call bar stays hidden,
 * header and hero CTAs remain functional).
 */
document.addEventListener('DOMContentLoaded', function () {
  'use strict';

  var hero = document.querySelector('.hero');
  var callBar = document.querySelector('.mobile-call-bar');
  if (!hero || !callBar) return;

  // IntersectionObserver: show the mobile call bar when the hero
  // scrolls fully out of the viewport.
  // isIntersecting === false means the hero has scrolled past.
  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (!entry.isIntersecting) {
        callBar.classList.add('is-visible');
      } else {
        callBar.classList.remove('is-visible');
      }
    });
  }, {
    rootMargin: '0px 0px 0px 0px',
    threshold: 0
  });

  observer.observe(hero);
});