import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="joern2sarif",
    version="1.0.3",
    author="Prabhu Subramanian",
    author_email="prabhu@shiftleft.io",
    description="Utility script to convert joern/ocular json output to sarif.",
    entry_points={"console_scripts": ["joern2sarif=joern2sarif.cli:main"]},
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/joernio/joern2sarif",
    packages=["joern2sarif", "joern2sarif.lib"],
    include_package_data=True,
    install_requires=["sarif-om", "jschema_to_python", "rich", "six"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Utilities",
        "Topic :: Security",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
