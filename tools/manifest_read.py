import struct,re
ANDROID_NS="http://schemas.android.com/apk/res/android"
NO_STRING=0xffffffff

def manifest_attributes(data, include_application=False):
    """Read the actual binary AndroidManifest.xml; no third party imports."""
    if len(data) < 8:
        raise ValueError("truncated Android manifest")
    file_type, header_size, file_size = struct.unpack_from("<HHI", data)
    if file_type != 0x0003 or header_size < 8 or file_size != len(data):
        raise ValueError("manifest is not a complete binary XML file")
    strings = None
    result = None
    application_seen = False
    application_name = None

    def need(pos, count, limit):
        if pos < 0 or count < 0 or pos + count > limit:
            raise ValueError("AXML chunk bounds exceeded")

    def length8(pos, limit):
        need(pos, 1, limit)
        first = data[pos]
        pos += 1
        if first & 0x80:
            need(pos, 1, limit)
            return ((first & 0x7f) << 8) | data[pos], pos + 1
        return first, pos

    def length16(pos, limit):
        need(pos, 2, limit)
        first = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if first & 0x8000:
            need(pos, 2, limit)
            return ((first & 0x7fff) << 16) | struct.unpack_from("<H", data, pos)[0], pos + 2
        return first, pos

    def string(index):
        if strings is None or not 0 <= index < len(strings):
            raise ValueError("invalid AXML string index")
        return strings[index]

    pos = header_size
    while pos < file_size:
        need(pos, 8, file_size)
        kind, header, size = struct.unpack_from("<HHI", data, pos)
        if header < 8 or size < header:
            raise ValueError("invalid AXML chunk size")
        end = pos + size
        need(pos, size, file_size)
        if kind == 0x0001:
            if strings is not None or header < 28:
                raise ValueError("invalid or duplicate AXML string pool")
            count, style_count, flags, start, style_start = struct.unpack_from("<IIIII", data, pos + 8)
            need(pos + header, count * 4 + style_count * 4, end)
            if start < header + 4 * (count + style_count) or start > size:
                raise ValueError("invalid string pool data offset")
            string_limit = pos + style_start if style_start else end
            if not pos + start <= string_limit <= end:
                raise ValueError("invalid string pool style offset")
            strings = []
            for i in range(count):
                offset = struct.unpack_from("<I", data, pos + header + i * 4)[0]
                cursor = pos + start + offset
                if flags & 0x100:
                    _, cursor = length8(cursor, string_limit)
                    count_bytes, cursor = length8(cursor, string_limit)
                    need(cursor, count_bytes + 1, string_limit)
                    if data[cursor + count_bytes] != 0:
                        raise ValueError("missing UTF-8 string terminator")
                    strings.append(data[cursor:cursor + count_bytes].decode("utf-8"))
                else:
                    count_chars, cursor = length16(cursor, string_limit)
                    count_bytes = count_chars * 2
                    need(cursor, count_bytes + 2, string_limit)
                    if data[cursor + count_bytes:cursor + count_bytes + 2] != b"\0\0":
                        raise ValueError("missing UTF-16 string terminator")
                    strings.append(data[cursor:cursor + count_bytes].decode("utf-16le"))
        elif kind == 0x0102:
            if header < 16:
                raise ValueError("invalid XML node header")
            extension = pos + header
            need(extension, 20, end)
            _, element_name, attr_start, attr_size, attr_count, _, _, _ = struct.unpack_from("<IIHHHHHH", data, extension)
            if attr_size < 20:
                raise ValueError("invalid manifest attribute size")
            first_attr = extension + attr_start
            need(first_attr, attr_size * attr_count, end)
            element = string(element_name)
            if element == "manifest":
                if result is not None:
                    raise ValueError("duplicate manifest element")
                result = {}
                for i in range(attr_count):
                    location = first_attr + i * attr_size
                    namespace, name, raw, value_size, zero, value_type, value = struct.unpack_from("<IIIHBBI", data, location)
                    if value_size != 8 or zero != 0:
                        raise ValueError("invalid AXML typed value")
                    key = string(name)
                    ns = "" if namespace == NO_STRING else string(namespace)
                    if key == "package" and ns == "" or key in {"versionCode", "versionName", "versionCodeMajor"} and ns == ANDROID_NS:
                        if key in result:
                            raise ValueError("duplicate manifest field")
                        if raw != NO_STRING:
                            resolved = string(raw)
                        elif value_type == 0x03:
                            resolved = string(value)
                        elif value_type in (0x10, 0x11):
                            resolved = value
                        else:
                            raise ValueError("version/package field is not a literal")
                        result[key] = resolved
            elif element == "application":
                if application_seen:
                    raise ValueError("duplicate application element")
                application_seen = True
                for i in range(attr_count):
                    location = first_attr + i * attr_size
                    namespace, name, raw, value_size, zero, value_type, value = struct.unpack_from("<IIIHBBI", data, location)
                    ns = "" if namespace == NO_STRING else string(namespace)
                    if string(name) == "name" and ns == ANDROID_NS:
                        if application_name is not None or value_size != 8 or zero != 0 or value_type != 0x03:
                            raise ValueError("invalid or duplicate literal Application name")
                        application_name = string(value)
                        if raw != NO_STRING and string(raw) != application_name:
                            raise ValueError("Application raw/typed name disagreement")
        pos = end
    if result is None or not {"package", "versionCode", "versionName"} <= result.keys():
        raise ValueError("manifest is missing literal package/version fields")
    result["versionCode"] = int(result["versionCode"])
    if int(result.get("versionCodeMajor", 0)) != 0:
        raise ValueError("this channel requires a 32-bit versionCode")
    if result["versionCode"] <= 0 or not re.fullmatch(r"[A-Za-z0-9_.]+", str(result["package"])):
        raise ValueError("invalid package/versionCode")
    if not re.fullmatch(r"[1-9][0-9]{0,3}\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})", str(result["versionName"])):
        raise ValueError("channel requires a literal major.minor.patch versionName")
    if include_application:
        if not application_seen or not application_name or not re.fullmatch(r"\.?[A-Za-z_$][A-Za-z0-9_.$]*", application_name):
            raise ValueError("manifest is missing a literal Application entry")
        if application_name.startswith("."):
            application_name = result["package"] + application_name
        elif "." not in application_name:
            application_name = result["package"] + "." + application_name
        result["applicationName"] = application_name
    return result
