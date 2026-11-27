"""Build-time improvements: parallel Cython compile (Web) and Core layer order.

Isolated: the job-count function is loaded from packaging/compile_runtime.py
without running the compile (the script compiles and deletes sources under
/app, so it is never executed here); the Dockerfile is checked structurally.
A real BuildKit comparison of the Core order is described in
docs/BUILD_SPEED_20261127.md.
"""
import ast
import os
import re
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
COMPILE = ROOT / 'packaging/compile_runtime.py'


def load_compile_jobs():
    tree = ast.parse(COMPILE.read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'compile_jobs')
    ns = {'os': os, 'Path': Path}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(COMPILE), 'exec'), ns)
    return ns['compile_jobs']


class CompileJobsTests(unittest.TestCase):
    def setUp(self):
        self.jobs = load_compile_jobs()

    def run_with(self, cpus, mem_kib, env=''):
        meminfo = f'MemTotal: 99999999 kB\nMemAvailable: {mem_kib} kB\n'
        with patch.dict(os.environ, {'ALPHA_COMPILE_JOBS': env}), \
                patch('os.sched_getaffinity', return_value=set(range(cpus))), \
                patch.object(Path, 'read_text', return_value=meminfo):
            return self.jobs()

    def test_one_job_per_cpu_capped_by_memory_and_eight(self):
        gib = 1024 * 1024
        self.assertEqual(self.run_with(4, 16 * gib), 4)
        self.assertEqual(self.run_with(16, 64 * gib), 8)
        self.assertEqual(self.run_with(8, 3 * gib), 3, 'about 1 GiB per compiler process')
        self.assertEqual(self.run_with(4, 500 * 1024), 1)
        self.assertEqual(self.run_with(1, 64 * gib), 1)

    def test_explicit_override(self):
        self.assertEqual(self.run_with(16, 64 * 1024 * 1024, env='2'), 2)
        for bad in ('0', '-3', 'x', ' '):
            self.assertEqual(self.run_with(4, 16 * 1024 * 1024, env=bad), 4, bad)

    def test_unreadable_meminfo_falls_back_to_cpus(self):
        with patch.dict(os.environ, {'ALPHA_COMPILE_JOBS': ''}), \
                patch('os.sched_getaffinity', return_value={0, 1}), \
                patch.object(Path, 'read_text', side_effect=OSError):
            self.assertEqual(self.jobs(), 2)

    def test_jobs_drive_both_cython_and_the_c_compiler(self):
        text = COMPILE.read_text(encoding='utf-8')
        self.assertIn('nthreads=jobs', text)
        self.assertIn("'--parallel', str(jobs)", text)
        self.assertNotIn('nthreads=1', text)
        dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        arg = dockerfile.index('ARG ALPHA_COMPILE_JOBS=')
        self.assertLess(arg, dockerfile.index('python /opt/alpha-build/compile_runtime.py'))
        self.assertGreater(arg, dockerfile.index('COPY packaging/ /opt/alpha-build/'), 'after the cached layers')


class CoreLayerOrderTests(unittest.TestCase):
    def stages(self):
        text = (ROOT / 'docker/freeradius/Dockerfile').read_text(encoding='utf-8')
        parts = re.split(r'^FROM ', text, flags=re.M)[1:]
        return {(p.split()[2] if ' AS ' in p.split('\n')[0] else 'final'): p for p in parts}

    def test_compile_stage_never_sees_configuration_files(self):
        stages = self.stages()
        self.assertEqual(list(stages), ['radius-base', 'detail-build', 'final'])
        self.assertTrue(stages['detail-build'].startswith('radius-base AS detail-build'))
        self.assertTrue(stages['final'].startswith('radius-base'))
        configs = ('entrypoint.sh', 'license-capacity-postauth.conf', 'alpha-accounting-identity.conf',
                   'alpha-realm-policy.conf', 'queries.conf', 'COPY detail ')
        for name in configs:
            self.assertNotIn(name, stages['radius-base'], name)
            self.assertNotIn(name, stages['detail-build'], name)
            self.assertIn(name, stages['final'], name)
        final = stages['final']
        self.assertLess(final.index('COPY --from=detail-build'), final.index('COPY entrypoint.sh'),
                        'rarely-changing layers first')
        for line in ('ENTRYPOINT ["/entrypoint.sh"]', 'WORKDIR /etc/freeradius/3.0', 'EXPOSE 1812/udp',
                     'EXPOSE 1813/udp', 'RUN chmod +x /entrypoint.sh',
                     'COPY --from=detail-build /build/detail/rlm_detail.so /usr/lib/freeradius/rlm_detail.so'):
            self.assertIn(line, final)


if __name__ == '__main__':
    unittest.main()
