#!/bin/bash
# 上传模型文件到GitHub Releases

# 配置
OWNER="MSG-change"
REPO="GrabOrderApp"
MODEL_FILE="best_siamese_model.pth"
VERSION="v1.7.2"
RELEASE_NAME="Model Files for v1.7.2"
RELEASE_BODY="This release contains the Siamese model file required for the nine-grid verification system.

## Model Information
- **File**: best_siamese_model.pth
- **Size**: 137.44 MB
- **Accuracy**: 98.88%
- **Purpose**: Nine-grid image recognition for Geetest verification

## Installation
1. Download the model file from this release
2. Place it in the root directory of GrabOrderApp
3. Build the APK normally

## Note
This file is too large to be included in the git repository, so it's hosted separately in this release."

# 检查文件是否存在
if [ ! -f "$MODEL_FILE" ]; then
    echo "❌ Model file not found: $MODEL_FILE"
    exit 1
fi

echo "📦 Uploading model to GitHub Release..."
echo "   Repository: $OWNER/$REPO"
echo "   Version: $VERSION"
echo "   File: $MODEL_FILE"

# 检查是否安装了gh CLI
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) is not installed"
    echo "   Install it with: brew install gh"
    echo "   Or visit: https://cli.github.com/"
    exit 1
fi

# 检查是否已登录
if ! gh auth status &> /dev/null; then
    echo "⚠️  Not logged in to GitHub CLI"
    echo "   Please run: gh auth login"
    exit 1
fi

# 创建release（如果不存在）
echo "Creating release $VERSION..."
gh release create "$VERSION" \
    --repo "$OWNER/$REPO" \
    --title "$RELEASE_NAME" \
    --notes "$RELEASE_BODY" \
    --draft=false \
    --prerelease=false \
    2>/dev/null || echo "Release may already exist, continuing..."

# 上传文件到release
echo "Uploading $MODEL_FILE to release..."
gh release upload "$VERSION" \
    "$MODEL_FILE" \
    --repo "$OWNER/$REPO" \
    --clobber

if [ $? -eq 0 ]; then
    echo "✅ Successfully uploaded!"
    echo "   Download URL: https://github.com/$OWNER/$REPO/releases/download/$VERSION/$MODEL_FILE"
else
    echo "❌ Upload failed"
    exit 1
fi
