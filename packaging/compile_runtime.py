"""Build proprietary modules without changing Python annotation semantics."""
from pathlib import Path
import os
import sysconfig

from Cython.Build import cythonize
from setuptools import Extension, setup

root = Path('/app')


def compile_jobs():
    """Parallel compiler processes: ALPHA_COMPILE_JOBS, else one per CPU,
    capped at 8 and at about 1 GiB of available memory per process."""
    requested = os.environ.get('ALPHA_COMPILE_JOBS', '').strip()
    if requested.isdigit() and int(requested) > 0:
        return int(requested)
    try:
        cpus = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        cpus = os.cpu_count() or 1
    by_memory = cpus
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):
                by_memory = max(1, int(line.split()[1]) // (1024 * 1024))
                break
    except (OSError, ValueError, IndexError):
        pass
    return max(1, min(cpus, by_memory, 8))


jobs = compile_jobs()
print(f'Compiling with {jobs} parallel job(s)', flush=True)
sources = sorted(p for p in root.rglob('*.py')
                 if not {'build', 'storage', 'uploads', '__pycache__'}.intersection(p.relative_to(root).parts))
extensions, packages = [], []
for path in sources:
    relative = path.relative_to(root)
    name = '.'.join(relative.with_suffix('').parts)
    if path.name == '__init__.py':
        name = '.'.join(relative.parent.parts)
        packages.append((name, path.parent))
    extensions.append(Extension(name, [str(path)], extra_compile_args=['-O1']))

setup(name='MAXProtectedRuntime', ext_modules=cythonize(
    extensions, nthreads=jobs, compiler_directives={
        'language_level': 3, 'annotation_typing': False, 'infer_types': False,
        'binding': True, 'always_allow_keywords': True, 'overflowcheck': True,
        'boundscheck': True, 'wraparound': True,
    }), script_args=['build_ext', '--inplace', '--parallel', str(jobs)])
suffix = sysconfig.get_config_var('EXT_SUFFIX')
for name, folder in packages:
    (root / (name.replace('.', '/') + suffix)).replace(folder / ('__init__' + suffix))

# All deletion is confined to disposable /app in the build stage.
import shutil
shutil.rmtree(root / 'build', ignore_errors=True)
for path in root.rglob('*'):
    if path.is_file() and path.suffix in {'.py', '.pyc', '.pyo', '.c'}:
        path.unlink()
assert not list(root.rglob('*.py'))
