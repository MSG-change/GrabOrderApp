"""
自定义 numpy recipe
跳过 libffi 编译问题
"""

from pythonforandroid.recipes.numpy import NumpyRecipe
import os
from os.path import join


class CustomNumpyRecipe(NumpyRecipe):
    """修改后的numpy recipe，跳过libffi编译"""
    
    version = '1.21.4'
    patches = ['skip_libffi.patch']
    
    def get_recipe_env(self, arch=None):
        """设置环境变量以跳过libffi编译"""
        env = super().get_recipe_env(arch)
        
        # 完全禁用BLAS/LAPACK，避免依赖
        env['NPY_BLAS_ORDER'] = ''
        env['NPY_LAPACK_ORDER'] = ''
        env['NUMPY_MADVISE_HUGEPAGE'] = '0'
        env['NPY_DISABLE_SVML'] = '1'
        
        # 跳过Fortran编译器检查
        env['NPY_NO_FORTRAN'] = '1'
        
        return env
    
    def prebuild_arch(self, arch):
        """构建前准备"""
        super().prebuild_arch(arch)
        
        # 创建site.cfg文件，告诉numpy不要寻找BLAS/LAPACK
        build_dir = self.get_build_dir(arch.arch)
        site_cfg = join(build_dir, 'site.cfg')
        
        with open(site_cfg, 'w') as f:
            f.write('[DEFAULT]\n')
            f.write('library_dirs =\n')
            f.write('include_dirs =\n')
            f.write('\n')
            f.write('[openblas]\n')
            f.write('libraries =\n')
            f.write('library_dirs =\n')
            f.write('include_dirs =\n')
            f.write('\n')
            f.write('[atlas]\n')
            f.write('libraries =\n')
            f.write('library_dirs =\n')
            f.write('include_dirs =\n')
        
        print(f"✅ Created site.cfg at {site_cfg}")


recipe = CustomNumpyRecipe()

