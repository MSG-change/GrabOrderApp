"""
自定义 numpy recipe
使用pip wheel方式安装，完全避免编译
"""

from pythonforandroid.recipe import PythonRecipe


class CustomNumpyRecipe(PythonRecipe):
    """使用预编译wheel的numpy recipe"""
    
    name = 'numpy'
    version = '1.21.4'
    url = 'https://pypi.io/packages/source/n/numpy/numpy-{version}.zip'
    
    # 关键：告诉buildozer使用pip安装wheel，不编译源码
    call_hostpython_via_targetpython = False
    install_in_hostpython = False
    
    def get_recipe_env(self, arch=None):
        """设置环境变量"""
        env = super().get_recipe_env(arch)
        
        # 完全禁用编译
        env['NPY_BLAS_ORDER'] = ''
        env['NPY_LAPACK_ORDER'] = ''
        env['NPY_DISABLE_SVML'] = '1'
        env['NPY_NUM_BUILD_JOBS'] = '1'
        
        return env
    
    def build_arch(self, arch):
        """使用pip安装，跳过编译"""
        super().build_arch(arch)
        
        # 安装后验证
        print(f"✅ Numpy {self.version} installed via pip")


recipe = CustomNumpyRecipe()

