def cvss_for(family:str, ev)->dict:
    if family=="xss":
        return {"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","base":6.1}
    if family=="sqli":
        return {"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L","base":9.1}
    if family=="redirect":
        return {"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N","base":5.4}
    return {"vector":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N","base":3.1}