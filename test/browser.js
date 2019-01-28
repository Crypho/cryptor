const webdriver = require('selenium-webdriver')

const testUrl = `file://${__dirname}/index.html`

function testsFinished() {
  return new webdriver.Condition('for tests to finish', driver => {
    return driver.executeScript('return window.testComplete')
  })
}

async function getCount(driver, category) {
  const el = await driver.findElement(webdriver.By.css(`#mocha-stats .${category} em`))
  return el.getText()
}

async function runTests() {
  const driver = new webdriver.Builder().forBrowser('chrome').build()
  try {
    console.log(`Running tests from ${testUrl}`)
    await driver.get(testUrl)
    await driver.wait(testsFinished())

    const tests = await driver.findElements(webdriver.By.css('.test'))
    for (let i = 0; i < tests.length; i++) {
      const tst = tests[i]
      const className = await tst.getAttribute('class')
      const classList = className.split(/\s+/)
      const header = await tst.findElement(webdriver.By.css('h2'))
      const tstName = (await header.getText()).slice(0, -2).replace(/\d+mss*$/, '')
      const prefix = classList.includes('pass') ? '✓' : '✖'
      console.log(`${prefix} ${tstName}`)
    }

    const failures = await getCount(driver, 'failures')
    const passes = await getCount(driver, 'passes')
    console.log(`Passes: ${passes}`)
    console.log(`Failures: ${failures}`)

    if (failures) {
      process.exitCode = 1
    }
  } finally {
    await driver.quit()
  }
}

runTests()
