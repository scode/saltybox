#!/bin/bash

set -euo pipefail


tmpdir=$(mktemp -d)
cleanup_tmp() {
    rm -rf "${tmpdir}"
}
trap cleanup_tmp EXIT

#- name: decrypt known cipher text
echo -n test | ./saltybox --passphrase-stdin decrypt -i testdata/hello.txt.salty -o "${tmpdir}/hello-decrypted1.txt"
diff testdata/hello.txt "${tmpdir}/hello-decrypted1.txt"

#- name: encrypt + decrypt known plain text
echo -n test | ./saltybox --passphrase-stdin encrypt -i testdata/hello.txt -o "${tmpdir}/hello-encrypted2.txt.salty"
echo -n test | ./saltybox --passphrase-stdin decrypt -i "${tmpdir}/hello-encrypted2.txt.salty" -o "${tmpdir}/hello-decrypted2.txt"
diff testdata/hello.txt "${tmpdir}/hello-decrypted2.txt"

# update works and only reads passphrase once
echo "updated data" > "${tmpdir}/updated_data.txt"
echo -n test | ./saltybox --passphrase-stdin update -i "${tmpdir}/updated_data.txt" -o "${tmpdir}/hello-encrypted2.txt.salty"
echo -n test | ./saltybox --passphrase-stdin decrypt -i "${tmpdir}/hello-encrypted2.txt.salty" -o "${tmpdir}/updated_data-decrypted.txt"
diff "${tmpdir}/updated_data.txt" "${tmpdir}/updated_data-decrypted.txt"

# ensure we exit with non-zero in case of errors
if ./saltybox --passphrase-stdin decrypt -i testdata/nonexistent.salty -o foo 2>/dev/null; then
    echo "saltybox should have failed (decrypting non-existent file) but it succeeded" >&2
    exit 1
fi
