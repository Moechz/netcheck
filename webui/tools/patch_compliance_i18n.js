#!/usr/bin/env node
/**
 * Inject the compliance-dossier i18n keys into every shipped language pack.
 *
 * webui/assets/i18n.js is the shipping source of truth (23 packs, including the
 * RTL ar-SA/he-IL packs that were added after webui/tools/gen_i18n.py was
 * written). This script is idempotent: it rewrites only the three
 * `about.compliance*` keys and leaves every other key and the rest of the file
 * byte-identical. Run it after editing the translations below:
 *
 *   node webui/tools/patch_compliance_i18n.js
 *   node webui/tools/check_i18n.js
 */
const fs = require("fs"), vm = require("vm");
const path = "webui/assets/i18n.js";
const src = fs.readFileSync(path, "utf8");
const ctx = { navigator: { language: "en-US", languages: [] },
              document: { documentElement: {} },
              localStorage: { getItem: () => null, setItem: () => {} } };
vm.createContext(ctx);
vm.runInContext(src + "\n;globalThis.__I18N = I18N; globalThis.__LOCALES = LOCALES;", ctx);
const I18N = ctx.__I18N, LOCALES = ctx.__LOCALES;

const KEYS = {
  "about.compliance": {
    "zh-CN":"合规与政策","zh-HK":"合規與政策","en-US":"Compliance & Policies",
    "de-DE":"Compliance & Richtlinien","fr-FR":"Conformité et politiques",
    "es-ES":"Cumplimiento y políticas","it-IT":"Conformità e policy",
    "tr-TR":"Uyumluluk ve politikalar","pt-PT":"Conformidade e políticas",
    "hu-HU":"Megfelelőség és szabályzatok","pl-PL":"Zgodność i polityki",
    "ru-RU":"Соответствие и политики","ja-JP":"コンプライアンスとポリシー",
    "ko-KR":"규정 준수 및 정책","nb-NO":"Samsvar og retningslinjer",
    "sv-SE":"Efterlevnad och policyer","nl-NL":"Compliance en beleid",
    "cs-CZ":"Soulad a zásady","vi-VN":"Tuân thủ và chính sách",
    "id-ID":"Kepatuhan & kebijakan","th-TH":"การปฏิบัติตามข้อกำหนดและนโยบาย",
    "ar-SA":"الالتزام والسياسات","he-IL":"תאימות ומדיניות"},
  "about.complianceHint": {
    "zh-CN":"隐私政策、第三方服务与数据去向、开源许可与依赖声明、用户数据查阅/更正/删除途径，以及特权通道（root 辅助服务）的授权依据与最小权限说明。",
    "zh-HK":"隱私政策、第三方服務與資料去向、開源授權與相依聲明、使用者資料查閱/更正/刪除途徑，以及特權通道（root 輔助服務）的授權依據與最小權限說明。",
    "en-US":"Privacy policy, third-party services and data flows, open-source licenses and dependency notices, user data access/correction/deletion, plus the authorisation basis and least-privilege notes for the privileged (root) helper service.",
    "de-DE":"Datenschutzerklärung, Dienste Dritter und Datenflüsse, Open-Source-Lizenzen und Abhängigkeiten, Zugriff/Korrektur/Löschung Ihrer Daten sowie Autorisierung und Minimalrechte des privilegierten (root) Hilfsdienstes.",
    "fr-FR":"Politique de confidentialité, services tiers et flux de données, licences open source et dépendances, accès/correction/suppression de vos données, ainsi que l’autorisation et les privilèges minimaux du service auxiliaire (root).",
    "es-ES":"Política de privacidad, servicios de terceros y flujos de datos, licencias de código abierto y dependencias, acceso/corrección/eliminación de sus datos, y la autorización y privilegios mínimos del servicio auxiliar (root).",
    "it-IT":"Informativa sulla privacy, servizi di terze parti e flussi di dati, licenze open source e dipendenze, accesso/correzione/eliminazione dei dati e autorizzazione con privilegi minimi del servizio ausiliario (root).",
    "tr-TR":"Gizlilik politikası, üçüncü taraf hizmetleri ve veri akışları, açık kaynak lisansları ve bağımlılıklar, veri erişimi/düzeltme/silme ve ayrıcalıklı (root) yardımcı servisin yetkilendirmesi ile en az yetki notları.",
    "pt-PT":"Política de privacidade, serviços de terceiros e fluxos de dados, licenças de código aberto e dependências, acesso/correção/eliminação dos seus dados e a autorização e privilégios mínimos do serviço auxiliar (root).",
    "hu-HU":"Adatvédelmi szabályzat, harmadik féltől származó szolgáltatások és adatáramlás, nyílt forráskódú licencek és függőségek, adathozzáférés/javítás/törlés, valamint a kiemelt (root) segédszolgáltatás engedélyezése és minimális jogosultságai.",
    "pl-PL":"Polityka prywatności, usługi i przepływy danych stron trzecich, licencje open source i zależności, dostęp/poprawianie/usuwanie danych oraz upoważnienie i minimalne uprawnienia usługi pomocniczej (root).",
    "ru-RU":"Политика конфиденциальности, сторонние службы и потоки данных, лицензии открытого кода и зависимости, доступ/исправление/удаление данных, а также авторизация и минимальные права вспомогательной службы (root).",
    "ja-JP":"プライバシーポリシー、第三者サービスとデータの流れ、オープンソースライセンスと依存関係、データの閲覧/訂正/削除、特権（root）補助サービスの認可根拠と最小権限の説明。",
    "ko-KR":"개인정보 처리방침, 제3자 서비스와 데이터 흐름, 오픈소스 라이선스와 의존성, 데이터 열람/정정/삭제, 그리고 특권(root) 보조 서비스의 승인 근거와 최소 권한 설명.",
    "nb-NO":"Personvernerklæring, tredjepartstjenester og dataflyt, åpen kildekode-lisenser og avhengigheter, innsyn/retting/sletting av data, samt autorisasjon og minsterettigheter for hjelpetjenesten (root).",
    "sv-SE":"Integritetspolicy, tredjepartstjänster och dataflöden, öppen källkodslicenser och beroenden, åtkomst/rättning/radering av data samt auktorisering och minimala rättigheter för hjälptjänsten (root).",
    "nl-NL":"Privacybeleid, diensten van derden en datastromen, open-sourcelicenties en afhankelijkheden, inzage/correctie/verwijdering van gegevens en de autorisatie en minimale rechten van de bevoorrechte (root) hulpdienst.",
    "cs-CZ":"Zásady ochrany osobních údajů, služby třetích stran a toky dat, open-source licence a závislosti, přístup/oprava/výmaz dat a autorizace a minimální oprávnění privilegované (root) pomocné služby.",
    "vi-VN":"Chính sách bảo mật, dịch vụ bên thứ ba và luồng dữ liệu, giấy phép mã nguồn mở và phụ thuộc, quyền truy cập/chỉnh sửa/xóa dữ liệu, cùng căn cứ uỷ quyền và quyền tối thiểu của dịch vụ hỗ trợ (root).",
    "id-ID":"Kebijakan privasi, layanan pihak ketiga dan aliran data, lisensi open source dan dependensi, akses/koreksi/penghapusan data, serta dasar otorisasi dan hak akses minimum layanan pembantu (root).",
    "th-TH":"นโยบายความเป็นส่วนตัว บริการบุคคลที่สามและเส้นทางข้อมูล สัญญาอนุญาตโอเพนซอร์สและ dependencies การเข้าถึง/แก้ไข/ลบข้อมูล รวมถึงเหตุผลการอนุญาตและสิทธิขั้นต่ำของบริการช่วย (root)",
    "ar-SA":"سياسة الخصوصية، وخدمات الأطراف الثالثة وتدفق البيانات، وتراخيص المصادر المفتوحة والاعتماديات، والوصول إلى بياناتك وتصحيحها وحذفها، وأساس الترخيص وأقل الصلاحيات لخدمة المساعدة (root).",
    "he-IL":"מדיניות פרטיות, שירותי צד שלישי וזרימת נתונים, רישיונות קוד פתוח ותלויות, גישה/תיקון/מחיקה של הנתונים, וכן בסיס ההרשאה והרשאות המינימום של שירות העזר (root)."},
  "about.complianceOpen": {
    "zh-CN":"打开合规与政策材料","zh-HK":"開啟合規與政策材料","en-US":"Open compliance & policy material",
    "de-DE":"Compliance-Material öffnen","fr-FR":"Ouvrir les documents de conformité",
    "es-ES":"Abrir materiales de cumplimiento","it-IT":"Apri i materiali di conformità",
    "tr-TR":"Uyumluluk belgelerini aç","pt-PT":"Abrir materiais de conformidade",
    "hu-HU":"Megfelelőségi anyagok megnyitása","pl-PL":"Otwórz materiały zgodności",
    "ru-RU":"Открыть материалы о соответствии","ja-JP":"コンプライアンス資料を開く",
    "ko-KR":"규정 준수 자료 열기","nb-NO":"Åpne samsvarsdokumenter",
    "sv-SE":"Öppna efterlevnadsdokument","nl-NL":"Compliance-materiaal openen",
    "cs-CZ":"Otevřít dokumenty o souladu","vi-VN":"Mở tài liệu tuân thủ",
    "id-ID":"Buka materi kepatuhan","th-TH":"เปิดเอกสารการปฏิบัติตามข้อกำหนด",
    "ar-SA":"افتح مواد الالتزام والسياسات","he-IL":"פתח חומרי תאימות ומדיניות"},
};

const codes = LOCALES.map(([code]) => code);
for (const code of codes) {
  const pack = I18N[code];
  if (!pack) throw new Error("missing pack " + code);
  for (const key of Object.keys(KEYS)) {
    if (pack[key] !== undefined) { delete pack[key]; }
    pack[key] = KEYS[key][code] || KEYS[key]["en-US"];
  }
}
if (codes.length !== 23) throw new Error("expected 23 packs, got " + codes.length);

const start = src.indexOf("const I18N = {");
const end = src.indexOf("\n};\n", start);
if (start < 0 || end < 0) throw new Error(
  "cannot locate the I18N block terminator (regenerate or repair webui/assets/i18n.js first)");
let block = "const I18N = {\n";
block += codes.map((code) => {
  const entries = Object.keys(I18N[code]).map(
    (k) => `\n  ${JSON.stringify(k)}:${JSON.stringify(I18N[code][k])}`);
  return `${JSON.stringify(code)}: {${entries.join(",")}\n}`;
}).join(",\n");
block += "\n}";
// `end` points at the "\n};\n" terminator: keep the ";" and the newline.
const updated = src.slice(0, start) + block + src.slice(end + 2);
fs.writeFileSync(path, updated);
console.log("patched i18n.js:", codes.length, "packs x", Object.keys(I18N["en-US"]).length, "keys");
