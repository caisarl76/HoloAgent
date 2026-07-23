from glob import glob

from setuptools import find_packages, setup


package_name = "holoagent_mujoco"

setup(
    name=package_name,
    version="0.1.0",
    packages=find_packages(exclude=["tests"]),
    data_files=[
        ("share/ament_index/resource_index/packages", [f"resource/{package_name}"]),
        (f"share/{package_name}", ["package.xml", "README.md"]),
        (f"share/{package_name}/config", glob("config/*.yaml")),
        (f"share/{package_name}/scripts", glob("scripts/*.sh")),
    ],
    install_requires=["setuptools", "numpy", "PyYAML"],
    zip_safe=True,
    maintainer="HoloAgent maintainers",
    maintainer_email="maintainers@example.com",
    description="Localhost-isolated ROS 2 bridge for the HoloAgent G1 MuJoCo contract.",
    license="Apache-2.0",
    tests_require=["pytest"],
    entry_points={
        "console_scripts": [
            "bridge_node = holoagent_mujoco.bridge_node:main",
            "stage1_eval = holoagent_mujoco.stage1_eval:main",
            "preflight = holoagent_mujoco.preflight:main",
            "generate_calibration = holoagent_mujoco.calibration:main",
        ]
    },
)
