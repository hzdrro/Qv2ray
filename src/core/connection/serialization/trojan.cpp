#include "core/CoreUtils.hpp"
#include "core/connection/Generation.hpp"
#include "core/connection/Serialization.hpp"
#include "utils/QvHelpers.hpp"

#define QV_MODULE_NAME "TrojanImporter"

namespace Qv2ray::core::connection
{
    namespace serialization::trojan
    {
        CONFIGROOT Deserialize(const QString &trojanUri, QString *alias, QString *errMessage)
        {
            TrojanServerObject server;
            QString d_name;

            if (trojanUri.length() < 9)
            {
                LOG("trojan:// string too short");
                *errMessage = QObject::tr("Trojan URI is too short");
            }

            auto uri = trojanUri.mid(9);
            auto hashPos = uri.lastIndexOf("#");
            DEBUG("Hash sign position: " + QSTRN(hashPos));

            if (hashPos >= 0)
            {
                // Get the name/remark
                d_name = uri.mid(uri.lastIndexOf("#") + 1);
                uri.truncate(hashPos);
            }

            auto questionmarkPos = uri.indexOf('?');
            DEBUG("Question mark sign position: " + QSTRN(questionmarkPos));

            if (questionmarkPos >= 0)
            {
                // ignore unsupported / non-standard parameters
                uri.truncate(questionmarkPos);
            }

            auto x = QUrl::fromUserInput(uri);
            server.address = x.host();
            server.port = x.port();

            const auto password = x.userName();
            server.password = password;

            d_name = QUrl::fromPercentEncoding(d_name.toUtf8());

            CONFIGROOT root;
            OUTBOUNDS outbounds;

            StreamSettingsObject stream;
            stream.security = "tls";

            outbounds.append(GenerateOutboundEntry(OUTBOUND_TAG_PROXY, "trojan", GenerateTrojanOUT({ server }), stream.toJson()));
            JADD(outbounds)
            *alias = alias->isEmpty() ? d_name : *alias + "_" + d_name;
            LOG("Deduced alias: " + *alias);
            return root;
        }

        const QString Serialize(const TrojanServerObject &server, const QString &alias)
        {
            QUrl url;
            const auto plainPassword = server.password;
            const auto password = plainPassword.toUtf8();
            url.setUserInfo(password);
            url.setScheme("trojan");
            url.setHost(server.address);
            url.setPort(server.port);
            url.setFragment(alias);
            return url.toString(QUrl::ComponentFormattingOption::FullyEncoded);
        }
    } // namespace serialization::trojan
} // namespace Qv2ray::core::connection
