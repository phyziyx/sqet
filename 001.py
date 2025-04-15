# Import all the dependencies...
from selenium import webdriver
import time

# Constants
WEBSITE_URL = 'https://selenium.dev'

# Setup the Selenium driver
driver = webdriver.Chrome()

# Visit our website
driver.get(WEBSITE_URL)

# Wait for few seconds
time.sleep(5)

# Print title of the results page
print("Page Title:", driver.title)

# Quit
driver.quit()
