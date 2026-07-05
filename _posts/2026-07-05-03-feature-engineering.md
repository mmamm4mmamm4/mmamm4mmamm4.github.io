---
title: 피처 엔지니어링 — House Prices Prediction
date: 2026-07-05 00:00:00 +0900
categories:
- Machine Learning
tags: []
author: mmamm4
---

# 피처 엔지니어링 — House Prices Prediction

전처리를 끝낼 때, 노트 끝에 다음 단계에서 처리할 항목을 정리해 뒀습니다. `Id`를 분리하지 않았고, 피처 이상치는 확인하지 않았으며, 숫자 형태의 범주형이 섞여 있고, 인코딩은 시작하지 않은 상태였습니다. 이번 노트는 그 항목들을 처리한 기록입니다.

전처리가 표의 결측치를 메우는 작업이었다면, 이번 단계는 목표가 다릅니다. 결측치를 채웠어도 모델은 아직 이 데이터를 그대로 사용할 수 없습니다. `ExterQual` 같은 열에 여전히 `"Gd"`, `"TA"` 같은 문자열이 들어 있기 때문입니다. 회귀 모델은 입력값을 수치 연산에 사용하므로, 문자열은 그대로 넣을 수 없습니다. 그래서 이번 단계의 목표는 한 문장으로 정리됩니다 — **사람이 읽는 표를 모델이 사용할 수 있는 숫자 행렬로 바꾸기.**

미리 적어두면, 이번 단계에서 시간을 가장 많이 쓴 부분은 인코딩 자체가 아니라 매핑 직후 결측치가 2,572개 생긴 문제였습니다. 원인과 해결은 해당 절에서 정리합니다.

---

## Id 열 분리

`Id`는 행을 식별하기 위한 번호입니다. 집값과 직접적인 관계가 없는데, 피처로 두면 모델이 이 값에서도 패턴을 찾으려 합니다. 우편번호가 큰 동네가 더 좋은 동네가 아니듯, `Id`가 크다고 비싼 집은 아닙니다. 그래서 피처에서 분리했습니다.

다만 test의 `Id`는 다릅니다. 캐글에 제출할 때 `Id,SalePrice` 형식이 필요하므로, test의 `Id`만 따로 보관했습니다.

```python
test_id = X_test["Id"].copy()          # 제출용으로 따로 보관
X_train = X_train.drop(columns=["Id"])
X_test  = X_test.drop(columns=["Id"])

print("train에 Id 남았나:", "Id" in X_train.columns)
print("보관한 test_id 처음 3개:", test_id.head(3).tolist())
```

```python
train에 Id 남았나: False
보관한 test_id 처음 3개: [1461, 1462, 1463]
```

`test_id`는 1461부터 시작합니다. train이 1~1460번이므로 그다음 번호이고, 보관이 정상적으로 됐다는 의미입니다. 이 단계에서 피처와 제출용 식별자를 분리했습니다.

---

## 이상치 확인 — 제거 전 시각화

전처리에서는 타겟(SalePrice) 분포만 확인했고, 피처 쪽 이상치는 별도로 확인하지 않았습니다. 이 데이터셋에서 자주 언급되는 이상치가 있는데, **거실 면적(`GrLivArea`)은 넓지만 가격은 낮은** 집 몇 채입니다.

회귀 모델은 데이터에 직선(또는 평면)을 맞추는데, 멀리 떨어진 소수의 점이 그 선에 큰 영향을 줄 수 있습니다. 이상치가 문제가 되는 이유는 데이터가 틀려서가 아니라, 이 소수 때문에 다수에 대한 예측 성능이 낮아질 수 있기 때문입니다.

고정 기준(`4000 이상` 등)만으로 제거하지 않고, 먼저 산점도로 분포를 확인했습니다.

```python
plt.scatter(X_train["GrLivArea"], y_train, s=10)
plt.xlabel("GrLivArea")
plt.ylabel("SalePrice (log)")
plt.show()
```

![fe_grlivarea_outliers.png](/assets/img/posts/2026-07-05-03-feature-engineering/fe_grlivarea_outliers.png)

(위 그림은 제거 대상을 빨간색으로 표시해 다시 그린 것입니다.) 점들은 대체로 오른쪽 위로 향합니다 — 면적이 넓을수록 가격이 높다는 경향입니다. 다만 면적이 4000을 넘는 구간에 다른 점들보다 낮게 위치한 점이 두 개 있습니다. 면적은 큰 편이지만 가격은 낮은 경우라, 회귀선에 영향을 줄 수 있습니다. 반대로 면적이 크면서 가격도 높은 점들(오른쪽 위)은 경향을 따르는 정상 데이터로 보고 제거하지 않았습니다.

제거 전에 대상이 두 점인지 표로 확인했습니다.

```python
cand = X_train[(X_train["GrLivArea"] > 4000) & (y_train < 12.5)]
cand"GrLivArea".assign(SalePrice_log=y_train.loc[cand.index])
```

| index | GrLivArea | SalePrice_log |
|------:|----------:|--------------:|
| 523 | 4676 | 12.127 |
| 1298 | 5642 | 11.983 |

대상은 두 채였습니다. 면적은 전체에서 가장 큰 축이지만 로그 가격은 11.98~12.13으로, 비슷한 면적의 다른 집들(대체로 12.5 이상)보다 낮습니다. 확인 후 제거했는데, 이때 주의할 점이 있습니다 — 피처만 제거하고 정답을 제거하지 않으면 두 데이터의 행 수가 어긋납니다.

```python
mask = (X_train["GrLivArea"] > 4000) & (y_train < 12.5)
X_train = X_train[~mask].reset_index(drop=True)
y_train = y_train[~mask].reset_index(drop=True)   # 같은 mask로 함께 제거

print("제거 후 X_train:", X_train.shape)
print("제거 후 y_train:", y_train.shape)
```

```python
제거 후 X_train: (1458, 79)
제거 후 y_train: (1458,)
```

`~mask`는 조건을 반전하는 표기로, 이상치만 제외하고 나머지를 남깁니다. 같은 `~mask`를 X와 y에 함께 적용했으므로 동일한 두 행이 제거되어 둘 다 1458행으로 일치합니다. 행을 제거할 때는 X와 y의 행 수를 함께 확인해야 합니다.

---

## 숫자 형태의 범주형 변수

전처리 노트에서 남겨둔 항목입니다. `MSSubClass`는 20, 60, 70 같은 정수이지만 크기가 아니라 주택 유형 코드입니다. 그대로 두면 모델이 "70은 20의 3.5배"처럼 잘못 해석합니다. 우편번호와 비슷한 성격입니다. `MoSold`(판매 월), `YrSold`(판매 연도)도 같은 경우입니다 — 12월이 1월의 12배는 아닙니다.

인코딩 전에 문자열로 변환해, 다음 단계에서 범주로 처리되게 했습니다.

```python
for col in ["MSSubClass", "MoSold", "YrSold"]:
    X_train[col] = X_train[col].astype(str)
    X_test[col]  = X_test[col].astype(str)

print(X_train"MSSubClass", "MoSold", "YrSold".dtypes)
```

```python
MSSubClass    object
MoSold        object
YrSold        object
dtype: object
```

세 열 모두 `object`(문자열)로 바뀌었습니다. 핵심 판단 기준은 값 사이의 크기나 순서가 실제로 의미가 있는지입니다.

---

## 인코딩 — 순서형과 명목형

이번 단계에서 가장 중요한 처리입니다. 문자열을 숫자로 바꾸는데, 범주를 모두 같은 방식으로 변환하면 안 됩니다. 범주에는 두 종류가 있습니다.

**순서형.** `ExterQual`(외벽 품질)은 `Ex(최상) > Gd > TA(보통) > Fa > Po(최악)` 순서가 있습니다. 품질이 높을수록 가격도 높은 경향이 있으므로, 순서대로 숫자를 매겨 그 정보를 전달합니다. 전처리에서 "시설 없음"을 `"None"`으로 채워둔 덕분에, `None=0`으로 두면 "없음 < 최악 < … < 최상"으로 이어집니다.

**명목형.** `Neighborhood`(동네)는 동네 사이에 순서가 없습니다. 순서 숫자를 매기면 없는 순서가 생기므로, 따로 처리합니다(뒤의 원-핫).

순서형부터 합니다. 사전(딕셔너리)을 만들어 `.map()`으로 변환하는데, `.map()`은 사전에 없는 값을 NaN으로 반환합니다. 그래서 전처리에서 `assert`로 확인했던 것처럼, 적용 전에 사전이 실제 값을 모두 포함하는지 점검했습니다.

```python
qual_map = {"None": 0, "Po": 1, "Fa": 2, "TA": 3, "Gd": 4, "Ex": 5}
qual_cols = ["ExterQual", "ExterCond", "BsmtQual", "BsmtCond",
             "HeatingQC", "KitchenQual", "FireplaceQu",
             "GarageQual", "GarageCond", "PoolQC"]

ordinal_maps = {
    "BsmtExposure": {"None":0, "No":1, "Mn":2, "Av":3, "Gd":4},
    "BsmtFinType1": {"None":0, "Unf":1, "LwQ":2, "Rec":3, "BLQ":4, "ALQ":5, "GLQ":6},
    "BsmtFinType2": {"None":0, "Unf":1, "LwQ":2, "Rec":3, "BLQ":4, "ALQ":5, "GLQ":6},
    "GarageFinish": {"None":0, "Unf":1, "RFn":2, "Fin":3},
    "Functional":   {"Sal":0, "Sev":1, "Maj2":2, "Maj1":3, "Mod":4, "Min2":5, "Min1":6, "Typ":7},
    "LotShape":     {"IR3":0, "IR2":1, "IR1":2, "Reg":3},
    "LandSlope":    {"Sev":0, "Mod":1, "Gtl":2},
    "PavedDrive":   {"N":0, "P":1, "Y":2},
    "CentralAir":   {"N":0, "Y":1},
}

# 사전에 없는 값이 데이터에 있는지 점검
for c in qual_cols:
    if c in X_train.columns:
        bad = set(X_train[c].dropna().unique()) - set(qual_map)
        if bad:
            print("[주의]", c, "에 사전에 없는 값:", bad)
```

점검에서 `[주의]` 줄이 출력되지 않았습니다. 모든 등급 값이 사전에 포함된다는 의미이므로, 이후 매핑을 적용했습니다.

```python
for c in qual_cols:
    if c in X_train.columns:
        X_train[c] = X_train[c].map(qual_map)
        X_test[c]  = X_test[c].map(qual_map)
for c, m in ordinal_maps.items():
    if c in X_train.columns:
        X_train[c] = X_train[c].map(m)
        X_test[c]  = X_test[c].map(m)

applied = [c for c in qual_cols + list(ordinal_maps) if c in X_train.columns]
print("매핑 후 NaN (train):", int(X_train[applied].isnull().sum().sum()))
print("매핑 후 NaN (test) :", int(X_test[applied].isnull().sum().sum()))
```

하지만 검산 결과 NaN이 남아 있었습니다.

```python
매핑 후 NaN (train): 2572
매핑 후 NaN (test) : 2637
```

점검을 통과했는데 매핑 후 결측이 2,572개 생겼습니다. 원인을 추가로 확인했습니다.

---

## NaN 2,572개의 원인 — 로딩 단계에서 사라진 "None"

먼저 NaN이 어디에서 발생했는지 확인했습니다. 무작위로 흩어졌는지, 특정 열에 몰렸는지 보았습니다.

```python
X_train[applied].isnull().sum()[lambda s: s > 0]
```

| 열 | NaN 개수 |
|----|------:|
| PoolQC | 1452 |
| FireplaceQu | 690 |
| GarageQual | 81 |
| GarageCond | 81 |
| GarageFinish | 81 |
| BsmtExposure | 38 |
| BsmtFinType2 | 38 |
| BsmtQual | 37 |
| BsmtCond | 37 |
| BsmtFinType1 | 37 |

NaN은 10개 열에만 나타났습니다. 이 10개 열의 공통점은 모두 전처리에서 "시설 없음"을 `"None"`으로 채운 열이라는 점입니다. 수영장이 없는 집 1,452채(PoolQC), 벽난로가 없는 집 690채(FireplaceQu), 차고가 없는 집 81채 등 전처리 노트의 숫자와 일치합니다. `"None"`이 있던 열에서만 발생한 문제였습니다.

원인은 데이터를 불러오는 단계에 있었습니다. `pd.read_csv`는 기본적으로 `""`, `"NA"`, `"null"` 같은 문자열을 결측으로 해석하는데, `"None"`도 그 목록에 포함됩니다. 따라서 전처리에서 문자열 `"None"`으로 채워 저장한 값이, 03에서 CSV를 불러오는 순간 다시 NaN으로 해석된 상태였습니다. 매핑 이전 단계에서 이미 값이 비어 있었던 것입니다.

점검을 통과한 이유는 점검 코드의 `.dropna()`에 있습니다.

```python
set(X_train[c].dropna().unique()) - set(qual_map)
```

`.dropna()`가 NaN을 제외하고 나머지(`Ex`, `Gd`, `TA` 등)만 확인했으므로, 그 값들은 모두 사전에 있어 문제가 없는 것으로 판단됐습니다. NaN을 본 것이 아니라 제외하고 본 것입니다. 그리고 `.map()`은 NaN을 그대로 NaN으로 반환합니다. 따라서 검산 코드에서는 NaN 자체도 별도로 확인해야 합니다.

수정은 CSV를 읽는 단계에서 했습니다. `keep_default_na=False`를 지정하면 pandas가 `"None"`을 문자열로 유지합니다.

```python
X_train = pd.read_csv(".../X_train_preprocessed.csv", keep_default_na=False).copy()
X_test  = pd.read_csv(".../X_test_preprocessed.csv",  keep_default_na=False).copy()
```

전처리에서 결측을 모두 채워 실제 빈 칸은 없으므로, 이 옵션의 부작용은 없습니다. 이 한 줄을 수정하고 ①~④를 다시 실행하니 검산 결과가 바뀌었습니다.

```python
매핑 후 NaN (train): 0
매핑 후 NaN (test) : 0
int64    19
```

NaN이 사라졌고, 매핑한 19개 열이 모두 정수(`int64`)가 됐습니다. 직전에는 NaN 때문에 일부가 실수(`float64`)로 섞여 있었습니다. `"None"`이 문자열로 유지되므로 사전의 `"None": 0`이 0(시설 없음)으로 매핑됐고, 전처리에서 의도한 "없음=등급 0" 매핑이 적용됐습니다.

---

## 명목형 원-핫 — 합치기는 누수가 아닙니다

순서 없는 범주(`Neighborhood`, `MSZoning` 등)는 다른 방식이 필요합니다. 동네가 25종이면 "이 집이 CollgCr인가(0/1)", "OldTown인가(0/1)"처럼 동네마다 0/1 열을 만듭니다. 한 집은 자기 동네 열만 1이고 나머지는 0이라, 객관식에서 정답 하나만 표시하는 것과 같아 원-핫(one-hot)이라고 합니다. 이렇게 하면 동네 사이에 순서가 생기지 않습니다.

`pd.get_dummies`로 처리하는데, 주의할 점이 있습니다. train과 test를 따로 펼치면, 어떤 동네가 한쪽에만 있을 경우 그 열도 한쪽에만 생겨 두 데이터의 열 구성이 어긋납니다. 이후 모델 입력에서 오류가 발생할 수 있습니다. 그래서 둘을 합쳐 한 번에 펼친 뒤 다시 나눴습니다.

```python
ntr = len(X_train)
combined = pd.concat([X_train, X_test], axis=0)   # 열 구조를 맞추기 위해 합침
combined = pd.get_dummies(combined, dtype=int)

X_train = combined.iloc[:ntr].reset_index(drop=True)
X_test  = combined.iloc[ntr:].reset_index(drop=True)

print("원-핫 후 X_train:", X_train.shape)
print("원-핫 후 X_test :", X_test.shape)
```

```python
원-핫 후 X_train: (1458, 258)
원-핫 후 X_test : (1459, 258)
```

여기서 train과 test를 합치는 것이 전처리에서 다룬 데이터 누수에 해당하는지 확인이 필요합니다. 다만 이 경우는 전처리 단계의 누수와 구분됩니다. 합치는 목적은 "어떤 동네 열이 존재하는가"라는 열 구조를 맞추는 것이고, test의 값을 사용해 train 통계를 계산하지 않습니다. 누수는 중앙값·최빈값·왜도 같은 통계값을 test까지 포함해 계산할 때 발생하며(전처리에서 train만 사용한 이유), 원-핫은 통계 계산이 아니라 "이 집은 이 동네"를 0/1로 표시하는 처리이므로 train 통계가 test로부터 계산되지는 않습니다. 정리하면 열 구조 정렬과 통계값 계산은 구분해야 합니다.

열이 79개에서 258개로 늘었는데, 동네·외장재 같은 명목형이 각각 0/1 열로 펼쳐졌기 때문입니다. train과 test의 열 개수가 258로 일치했습니다(행 수는 1458과 1459로 다릅니다).

---

## 치우친 수치형 로그 변환 — 처리 순서 보정

마지막으로 한쪽으로 길게 늘어진 수치형 피처를 로그로 변환했습니다. 전처리에서 타겟(SalePrice)에 적용한 것과 같은 이유입니다. 면적이나 부지 크기처럼 소수의 큰 값이 분포의 오른쪽 꼬리를 길게 만드는 피처는, 로그를 적용하면 정규분포에 가까워져 (특히 선형 모델에서) 도움이 됩니다.

다만 처리 순서 때문에 추가 필터링이 필요했습니다. 로그 변환은 원-핫보다 먼저 하는 것이 적절합니다. 원-핫 이후에는 0/1 더미 열이 200개 넘게 생기는데, 이 열도 수치형으로 분류됩니다. 0/1 열에 로그를 적용하는 것은 의미가 없습니다. 전체 과정을 다시 실행하는 대신, 로그 대상에서 더미 열(값이 0/1뿐)과 순서형으로 인코딩한 열을 제외하는 방식으로 처리했습니다.

```python
exclude = set(applied)   # 순서형으로 인코딩한 열
num_cols = [c for c in X_train.select_dtypes("number").columns
            if c not in exclude and X_train[c].nunique() > 2]

skew = X_train[num_cols].skew()              # 왜도는 train으로만 계산
skewed_cols = skew[skew.abs() > 0.75].index

X_train[skewed_cols] = np.log1p(X_train[skewed_cols])
X_test[skewed_cols]  = np.log1p(X_test[skewed_cols])   # 같은 열을 test에 동일 적용
```

`nunique() > 2`로 값이 3종류 이상인 열만 선택해 0/1 더미를 제외했습니다. 임계값 0.75를 넘는 20개 열이 선정됐고, 왜도가 큰 열은 다음과 같습니다.

| 열 | 왜도 |
|----|-----:|
| MiscVal | 24.46 |
| PoolArea | 15.95 |
| LotArea | 12.57 |
| 3SsnPorch | 10.30 |
| LowQualFinSF | 9.00 |
| KitchenAbvGr | 4.48 |
| BsmtFinSF2 | 4.25 |
| ScreenPorch | 4.12 |

부지 면적(`LotArea`)처럼 예상한 피처도 있고, `MiscVal`·`PoolArea`처럼 대부분의 집에서 0이라 왜도가 매우 큰 열도 있습니다. 왜도 계산도 train 기준으로만 수행했고, 선정된 열 목록을 test에 동일하게 적용했습니다. test를 보고 열을 선택하면 누수가 됩니다. 또한 `log` 대신 `log1p`(=`log(1+x)`)를 사용한 것은 면적에 0이 있어 `log(0)`이 정의되지 않는 경우를 피하기 위해서입니다.

---

## 최종 검산과 저장

단계가 많았으므로, 마지막에 모델 입력으로 사용할 수 있는 형태인지 항목별로 확인했습니다.

```python
print("1) 컬럼 일치     :", list(X_train.columns) == list(X_test.columns))
print("2) 남은 글자열   :", list(X_train.select_dtypes("object").columns))
print("3) 행수 일치(X,y):", len(X_train) == len(y_train))
print("5) NaN (train)   :", int(X_train.isnull().sum().sum()))
print("6) inf (train)   :", int(np.isinf(X_train.to_numpy()).sum()))
print("   최종 shape    :", X_train.shape, X_test.shape)
```

```python
1) 컬럼 일치     : True
2) 남은 글자열   : []
3) 행수 일치(X,y): True
5) NaN (train)   : 0
6) inf (train)   : 0
   최종 shape    : (1458, 258) (1459, 258)
```

중요하게 확인한 항목은 `2) 남은 글자열 : []`입니다. 빈 리스트, 즉 문자열 열이 남지 않아 모델 입력에 사용할 수 있는 숫자형 데이터가 됐다는 의미입니다. NaN과 inf도 0이므로, 결과를 다음 단계에서 사용하도록 파일로 저장했습니다.

```python
X_train.to_csv(".../X_train_fe.csv", index=False)
X_test.to_csv(".../X_test_fe.csv", index=False)
y_train.to_frame("SalePrice_log").to_csv(".../y_train_fe.csv", index=False)
test_id.to_csv(".../test_id.csv", index=False)
```

`_fe`는 feature engineering의 약자로, 전처리의 `_preprocessed`와 구분하기 위해 붙였습니다. 또한 `_fe` 파일은 다시 읽어도 앞서 발생한 `"None"`의 NaN 변환 문제가 재발하지 않습니다. 순서형은 0~5 숫자이고 명목형은 0/1이므로 문자열 `"None"`이 남아 있지 않기 때문입니다.

---

## 하고 나서야 보인 것들

정리하면서 다음 단계에서 검토할 항목이 남았습니다. 기록해 둡니다.

- **로그 변환은 원-핫보다 먼저 하는 것이 적절합니다.** 순서가 바뀌어 더미 열을 제외하는 단계가 추가됐습니다. 변환은 인코딩으로 열을 펼치기 전에 끝내는 것이 깔끔하며, 이번 처리 과정에서 그 점을 확인했습니다.

- **`read_csv`의 결측 처리 옵션을 확인해야 합니다.** 이번 NaN 문제의 원인이 여기 있었습니다. 전처리에서 `"None"` 대신 다른 표시(예: `"NoFeature"`)를 사용했다면 발생하지 않았을 문제입니다. 저장 형식과 로딩 옵션은 함께 설계해야 합니다.

- **순서형 임계값(skew 0.75)과 매핑은 추가로 검토할 수 있습니다.** 자주 쓰는 기준을 사용했는데, 0.5나 1.0일 때 점수가 어떻게 달라지는지 모델링 단계에서 비교할 예정입니다. `Functional`처럼 단계가 많은 순서형의 매핑이 적절한지도 확인이 필요합니다.

- **거의 한 값뿐인 열이 남아 있습니다.** `Utilities`처럼 사실상 한 값인 열은 원-핫을 하면 거의 0인 더미만 생깁니다. 전처리에서 정리하기로 한 "거의 상수" 열은 아직 제거하지 않았으며, 모델 성능을 보며 제거를 검토합니다.

- **순서형에는 로그를 적용하지 않았는데**, 적절한 선택인지 모델로 확인할 항목입니다. 등급 0~5는 범위가 좁아 변환이 필요 없다고 보았지만, 근거는 모델 성능으로 확인할 예정입니다.

---

## 다음 단계

- 데이터가 숫자 행렬(`_fe.csv`)이 됐으므로, 베이스라인 회귀(선형/릿지)부터 학습
- 로그 타겟(`SalePrice_log`)으로 점수가 어떻게 달라지는지 비교, 예측값은 `expm1`로 되돌려 평가
- 교차검증(CV)으로 일반화 성능 확인 후 XGBoost / LightGBM으로 확장
- 인코딩·스케일링을 train에서만 fit 하도록 `sklearn` Pipeline으로 묶어, 손으로 누수를 막는 대신 구조적으로 차단
- 거의 상수인 열 제거, 왜도 임계값·순서형 매핑 같은 선택지를 모델 성능으로 비교
