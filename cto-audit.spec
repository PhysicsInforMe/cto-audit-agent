# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file per CTO Audit Agent.

Genera un eseguibile standalone con dashboard integrata.
"""

import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

# Root del progetto
PROJECT_ROOT = os.path.dirname(os.path.abspath(SPEC))

# Dati YAML da includere
datas = [
    (os.path.join(PROJECT_ROOT, 'scoring-profiles'), 'scoring-profiles'),
    (os.path.join(PROJECT_ROOT, 'remediation-kb'), 'remediation-kb'),
    (os.path.join(PROJECT_ROOT, 'compliance-profiles'), 'compliance-profiles'),
]

# Includi asset Dash/Plotly/dbc
datas += collect_data_files('dash')
datas += collect_data_files('dash_bootstrap_components')
datas += collect_data_files('plotly')

# Hidden imports per moduli caricati dinamicamente
hiddenimports = [
    'cto_audit.dashboard',
    'cto_audit.dashboard.app',
    'cto_audit.dashboard.layout',
    'cto_audit.dashboard.theme',
    'cto_audit.dashboard.callbacks',
    'cto_audit.dashboard.components.overview',
    'cto_audit.dashboard.components.layers',
    'cto_audit.dashboard.components.findings',
    'cto_audit.dashboard.components.remediation',
    'cto_audit.dashboard.components.compliance',
    'cto_audit.dashboard.components.history',
    'cto_audit.dashboard.components.source_picker',
    'cto_audit.dashboard.components.project_view',
    'cto_audit.dashboard.components.guide',
    'cto_audit.sources.github',
    'cto_audit.sources.gitlab',
    'cto_audit.sources.azure_devops',
    'cto_audit.sources.bitbucket',
    'cto_audit.sources.archive',
    'cto_audit.reporters.json_export',
    'cto_audit.reporters.html',
    'cto_audit.reporters.markdown',
    'cto_audit.reporters.terminal',
    'cto_audit.reporters.board',
]

a = Analysis(
    [os.path.join(PROJECT_ROOT, 'src', 'cto_audit', 'exe_entry.py')],
    pathex=[os.path.join(PROJECT_ROOT, 'src')],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'torch', 'torchvision', 'torchaudio',
        'sklearn', 'scikit-learn',
        'transformers', 'tokenizers', 'huggingface_hub',
        'tensorflow', 'keras',
        'scipy',
        'numpy',
        'pandas',
        'matplotlib',
        'PIL', 'Pillow',
        'IPython', 'jupyter', 'notebook', 'nbformat', 'nbconvert',
        'sympy',
        'h5py',
        'numba', 'llvmlite',
        'statsmodels', 'patsy',
        'xarray',
        'pyarrow',
        'openpyxl',
        'altair',
        'datasets',
        'lightning', 'pytorch_lightning',
        'hydra', 'omegaconf',
        'sentence_transformers',
        'black', 'blib2to3',
        'pytest', 'py', '_pytest',
        'cloudpickle',
        'fsspec',
        'zmq',
        'lxml',
        'tkinter', '_tkinter',
        'einops',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='cto-audit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Nessuna finestra terminale
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
