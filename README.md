## Burp Suite - Extender

### 환경구성
- Burp Suite Professional (유로버전)
- Jython
    - Windows(http://www.jython.org/downloads.html - 다운로드)
    - Mac OS X ($ brew install jython - 터미널 설치)
    
#### Windows 환경 설정
1. Jython 홈페이지에서 jython x.x.x - `Standalon Jar`를 다운
2. Extender - Options - Python Environment 에서 다운받은 jar를 추가

#### Mac OS X 환경 설정
1. brew를 이용하여 jython 설치가 가능
    ```
    $ brew install jython
    ==> Downloading https://homebrew.bintray.com/bottles/jython-2.7.1.high_sierra.bottle.tar.gz
    ######################################################################## 100.0%
    ==> Pouring jython-2.7.1.high_sierra.bottle.tar.gz
    🍺  /usr/local/Cellar/jython/2.7.1: 3,797 files, 147.4MB
    ```
2. Extender - Options - Python Environment 에서 아래 경로의 jython.jar를 추가

    ```
    /usr/local/Cellar/jython/2.7.1/libexec/jython.jar
    ```
3. python 소스를 `Extender - Extensions - Burp Extensions`에 추가


### findMe
- searchItem 리스트 아이템을 자동 검색하여 Comment에 표시 가능
- searchItem 정규식/문자열/숫자 혼용 가능


