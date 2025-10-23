from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Create the ~/.parasort directory if it doesn't exist during installation
home_dir = os.path.expanduser("~")
config_dir = os.path.join(home_dir, ".parasort")
os.makedirs(config_dir, exist_ok=True)

# Copy the default config file to ~/.parasort if it doesn't exist
default_config_src = "parameter_categories.json"
default_config_dst = os.path.join(config_dir, "parameter_categories.json")

if os.path.exists(default_config_src) and not os.path.exists(default_config_dst):
    import shutil
    shutil.copy2(default_config_src, default_config_dst)
    print(f"Created default config file at: {default_config_dst}")

setup(
    name="parasort",
    version="1.5.0",
    author="Ev3rPalestine",
    author_email="Ev3rPalestine@gmail.com",
    description="URL Parameter Categorization and Extraction Tool for Penetration Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Ev3rPalestine/parasort",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Penetration Testing",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Bug Bounty",
        "Topic :: Pentesting",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.6",
    install_requires=[
        "colorama>=0.4.4",
    ],
    entry_points={
        "console_scripts": [
            "parasort=parasort.parasort:main",
        ],
    },
    include_package_data=True,
)