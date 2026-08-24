import { test } from '@playwright/test'
const T = 'admin-token-0000-0000-000000000001'
test('login first load', async ({ page }) => {
  await page.goto('/login'); await page.waitForLoadState('networkidle')
  const m = await page.evaluate(() => {
    const res = performance.getEntriesByType('resource') as PerformanceResourceTiming[]
    return { all: res.length, kb: Math.round(res.reduce((s,r)=>s+(r.transferSize||0),0)/1024),
             charts: res.some((r)=>/chart/i.test(r.name)) }
  })
  console.log(`login: ${m.all} requests, ${m.kb} kB, chartjs loaded: ${m.charts}`)
})
for (const path of ['/dashboard','/endpoints','/graph/users']) {
  test(`timing ${path}`, async ({ page }) => {
    await page.goto('/login')
    await page.evaluate((t)=>localStorage.setItem('s1_token',t), T)
    const t0=Date.now(); await page.goto(path); await page.waitForLoadState('networkidle')
    const m = await page.evaluate(() => {
      const res = performance.getEntriesByType('resource') as PerformanceResourceTiming[]
      return { js: res.filter((r)=>/\.js(\?|$)/.test(r.name)).length, all: res.length,
               kb: Math.round(res.reduce((s,r)=>s+(r.transferSize||0),0)/1024) }
    })
    console.log(`${path.padEnd(15)} ${String(Date.now()-t0).padStart(4)} ms  ${String(m.js).padStart(2)} js of ${String(m.all).padStart(2)} req  ${String(m.kb).padStart(4)} kB`)
  })
}
