from setuptools import find_packages, setup


package_name = "holoagent_livox_converter"

setup(
    name=package_name,
    version="0.1.0",
    packages=find_packages(exclude=["test"]),
    data_files=[
        ("share/ament_index/resource_index/packages", [f"resource/{package_name}"]),
        (f"share/{package_name}", ["package.xml"]),
    ],
    install_requires=["setuptools", "numpy"],
    zip_safe=True,
    maintainer="HoloAgent maintainers",
    maintainer_email="maintainers@example.com",
    description="Convert HoloAgent synthetic PointCloud2 scans to Livox CustomMsg.",
    license="Apache-2.0",
    tests_require=["pytest"],
    entry_points={
        "console_scripts": [
            "livox_converter = holoagent_livox_converter.converter_node:main",
            "stage2_eval = holoagent_livox_converter.stage2_eval:main",
        ]
    },
)
