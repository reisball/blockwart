const assert = require('node:assert/strict');

/**
 * Measure and assert usable local-search geometry in the rendered document.
 * @param {import('playwright').Page} page - Fixture page after native navigation.
 * @returns {Promise<object>} Rendered input, submit, header and create geometry.
 */
async function assertLocalSearchGeometry(page) {
  await page.locator('[data-local-search] input[name=q]').waitFor({state:'visible'});
  const geometry = await page.evaluate(() => {
    const box = el => {
      const r = el.getBoundingClientRect(), s = getComputedStyle(el);
      const hit = document.elementFromPoint(r.x+r.width/2, r.y+r.height/2);
      return {x:r.x,y:r.y,width:r.width,height:r.height,center:r.y+r.height/2,
        radius:s.borderRadius,padding:[s.paddingTop,s.paddingRight,s.paddingBottom,s.paddingLeft],
        hit:!!hit && (hit===el || el.contains(hit))};
    };
    const form = document.querySelector('[data-local-search]');
    return {clientWidth:document.documentElement.clientWidth,
      scrollWidth:document.documentElement.scrollWidth,
      input:box(form.querySelector('input[name=q]')),submit:box(form.querySelector('button')),
      header:[...document.querySelectorAll('.main-navigation a,.main-actions > a')].map(box),
      root:document.querySelector('.catalog-create-actions a') ?
        box(document.querySelector('.catalog-create-actions a')) : null};
  });
  assert(geometry.input.width >= 200, JSON.stringify(geometry));
  assert(geometry.input.hit && geometry.submit.hit, 'Search must be unobstructed');
  assert(geometry.scrollWidth <= geometry.clientWidth, 'No whole-page horizontal overflow: '+JSON.stringify(geometry));
  for (const control of geometry.header) {
    assert.equal(control.height,40);
    assert.equal(control.radius,'7px');
    assert.deepEqual(control.padding,['8px','12px','8px','12px']);
    assert(control.hit);
  }
  return geometry;
}

module.exports = {assertLocalSearchGeometry};
