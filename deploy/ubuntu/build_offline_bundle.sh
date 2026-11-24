#!/usr/bin/env bash
# ==============================================================================
# 📦 سكربت حزم منظومة ALPHA RADIUS للعمل بدون إنترنت (Offline Appliance Bundle)
# يقوم بتصدير صور الدوكر محلياً وحزم المشروع بالكامل لنقله وتثبيته فورياً
# ==============================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "===================================================================="
echo "    📦 تجهيز حزمة التثبيت الأوفلاين الشاملة لمنظومة ALPHA RADIUS"
echo "===================================================================="
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUNDLE_DIR="${PROJECT_ROOT}/alpha_radius_offline_bundle"

mkdir -p "${BUNDLE_DIR}/images"

echo -e "${YELLOW}[1/4] 🐳 بناء وحفظ صور الدوكر في ملفات أرشيف محلية...${NC}"
cd "${PROJECT_ROOT}"

# بناء أحدث الصور
docker compose build

# تصدير صور الدوكر إلى ملفات tar
echo "  💾 جاري تصدير صورة Web Dashboard..."
docker save alpha-radius-wisp-web:latest | gzip > "${BUNDLE_DIR}/images/alpha_web.tar.gz"

echo "  💾 جاري تصدير صورة FreeRADIUS Engine..."
docker save alpha-radius-freeradius:latest | gzip > "${BUNDLE_DIR}/images/alpha_radius.tar.gz"

echo "  💾 جاري تصدير صورة MariaDB Database..."
docker save mariadb:10.11 | gzip > "${BUNDLE_DIR}/images/mariadb.tar.gz"

echo -e "${YELLOW}[2/4] 📂 نسخ كود وملفات المشروع بالكامل...${NC}"
rsync -av --exclude='alpha_radius_offline_bundle' --exclude='.git' --exclude='__pycache__' --exclude='storage/logs/*' "${PROJECT_ROOT}/" "${BUNDLE_DIR}/project/"

echo -e "${YELLOW}[3/4] 📝 إنشاء سكربت التثبيت الأوفلاين السريع (offline_install.sh)...${NC}"
cat << 'EOF' > "${BUNDLE_DIR}/offline_install.sh"
#!/usr/bin/env bash
set -eo pipefail
export DEBIAN_FRONTEND=noninteractive

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo "❌ الرجاء تشغيل السكربت بصلاحيات الجذر (sudo ./offline_install.sh)"
    exit 1
fi

echo -e "${CYAN}${BOLD}🚀 جاري تثبيت ALPHA RADIUS Appliance محلياً بدون إنترنت...${NC}"

INSTALL_DIR="/opt/alpha-radius"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. نسخ ملفات المشروع
mkdir -p "${INSTALL_DIR}"
cp -r "${SCRIPT_DIR}/project/"* "${INSTALL_DIR}/"

# 2. استيراد صور الدوكر المحفوظة مسبقاً
echo -e "${YELLOW}🐳 جاري استيراد صور الدوكر المحفوظة محلياً...${NC}"
docker load < "${SCRIPT_DIR}/images/alpha_web.tar.gz"
docker load < "${SCRIPT_DIR}/images/alpha_radius.tar.gz"
docker load < "${SCRIPT_DIR}/images/mariadb.tar.gz"

# 3. إعداد Nginx والجدار الناري
echo -e "${YELLOW}🌐 إعداد خادم Nginx والمنفذ 80...${NC}"
cp -f "${INSTALL_DIR}/deploy/ubuntu/nginx.conf" /etc/nginx/sites-available/default
nginx -t > /dev/null 2>&1 || true
systemctl restart nginx || true
systemctl enable nginx || true

# 4. تثبيت أداة alphaip
cp -f "${INSTALL_DIR}/deploy/ubuntu/alphaip" /usr/local/bin/alphaip
chmod +x /usr/local/bin/alphaip

# 5. تشغيل الحاويات
cd "${INSTALL_DIR}"
docker compose up -d

# 6. حقن حساب max / max123
sleep 5
for i in {1..20}; do
    if docker exec alpha_radius_db mariadb -uradius -pradpass radius_wisp -e "SELECT 1" > /dev/null 2>&1; then
        break
    fi
    sleep 2
done
docker exec -i alpha_radius_db mariadb -uradius -pradpass radius_wisp < "${INSTALL_DIR}/deploy/ubuntu/init_admin.sql" 2>/dev/null || true

echo -e "${GREEN}${BOLD}====================================================================${NC}"
echo -e "${GREEN}${BOLD}  ✅ تم تجهيز السيرفر بالكامل! جاهز للاستخدام الفوري.${NC}"
echo -e "${GREEN}${BOLD}====================================================================${NC}"
echo -e "🔹 لتحديد عنوان IP السيرفر، اكتب في التيرمينال: ${BOLD}alphaip${NC}"
EOF

chmod +x "${BUNDLE_DIR}/offline_install.sh"

echo -e "${YELLOW}[4/4] 🗜️  ضغط الحزمة الكاملة في ملف واحد جاهز للنقل (alpha_radius_appliance.tar.gz)...${NC}"
cd "${PROJECT_ROOT}"
tar -czvf alpha_radius_appliance.tar.gz -C "${PROJECT_ROOT}" alpha_radius_offline_bundle > /dev/null

echo ""
echo -e "${GREEN}${BOLD}====================================================================${NC}"
echo -e "${GREEN}${BOLD}  🎉 تم إنشاء الحزمة الشاملة الجاهزة بنجاح!${NC}"
echo -e "${GREEN}${BOLD}  📦 الملف الناتج: alpha_radius_appliance.tar.gz${NC}"
echo -e "${GREEN}${BOLD}====================================================================${NC}"
